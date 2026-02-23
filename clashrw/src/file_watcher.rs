mod v1 {
    use crate::parser::UpdateConfigureEvent;
    use log::{debug, error, warn};
    use notify::{Event, RecursiveMode, Watcher};
    use std::path::PathBuf;
    use std::thread::JoinHandle;
    use std::time::Duration;

    #[derive(Debug)]
    pub struct FileWatchDog {
        handler: JoinHandle<Option<()>>,
        stop_signal_channel: oneshot::Sender<bool>,
    }

    impl FileWatchDog {
        pub fn file_watching(
            file: String,
            stop_signal_channel: oneshot::Receiver<bool>,
            sender: tokio::sync::mpsc::Sender<UpdateConfigureEvent>,
        ) -> Option<()> {
            let path = PathBuf::from(&file)
                .canonicalize()
                .inspect_err(|e| {
                    error!("[Can be safely ignored] Unable to canonicalize path: {e:?}")
                })
                .ok()?;
            let watch_dir = path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            let file_name = path.file_name()?.to_os_string();

            let mut watcher = notify::recommended_watcher(move |res| match res {
                Ok(event) => {
                    if Self::decide(&file_name, &event) {
                        tokio::runtime::Builder::new_current_thread()
                            .build()
                            .map(|runtime| runtime.block_on(Self::send_event(sender.clone())))
                            .inspect_err(|e| {
                                error!("[Can be safely ignored] Unable create runtime: {e:?}")
                            })
                            .ok();
                    }
                }
                Err(e) => {
                    error!(
                        "[Can be safely ignored] Got error while watching file {:?}",
                        e
                    )
                }
            })
            .inspect_err(|e| error!("[Can be safely ignored] Can't start watcher {e:?}"))
            .ok()?;

            watcher
                .watch(&watch_dir, RecursiveMode::NonRecursive)
                .inspect_err(|e| error!("[Can be safely ignored] Unable to watch file: {e:?}"))
                .ok()?;

            stop_signal_channel
                .recv()
                .inspect_err(|e| {
                    error!("[Can be safely ignored] Got error while poll oneshot event: {e:?}")
                })
                .ok();

            watcher
                .unwatch(&watch_dir)
                .inspect_err(|e| error!("[Can be safely ignored] Unable to unwatch file: {e:?}"))
                .ok()?;

            debug!("File watcher exited!");
            Some(())
        }

        fn decide(file_name: &std::ffi::OsStr, event: &Event) -> bool {
            let path_matches = event.paths.iter().any(|p| p.file_name() == Some(file_name));
            if !path_matches {
                return false;
            }
            if matches!(
                event.kind,
                notify::EventKind::Access(notify::event::AccessKind::Close(
                    notify::event::AccessMode::Write,
                )) | notify::EventKind::Create(_)
            ) {
                return true;
            }
            event.need_rescan()
        }

        async fn send_event(sender: tokio::sync::mpsc::Sender<UpdateConfigureEvent>) -> Option<()> {
            sender
                .send(UpdateConfigureEvent::NeedUpdate)
                .await
                .inspect_err(|_| {
                    error!("[Can be safely ignored] Got error while sending event to update thread")
                })
                .ok()
        }

        pub fn start(
            path: String,
            sender: tokio::sync::mpsc::Sender<UpdateConfigureEvent>,
        ) -> Self {
            let (stop_signal_channel, receiver) = oneshot::channel();
            Self {
                handler: std::thread::spawn(|| Self::file_watching(path, receiver, sender)),
                stop_signal_channel,
            }
        }

        pub fn stop(self) -> Option<()> {
            if !self.handler.is_finished() {
                self.stop_signal_channel
                    .send(true)
                    .inspect_err(|e| {
                        error!(
                "[Can be safely ignored] Unable send terminate signal to file watcher thread: {e:?}"
            )
                    })
                    .ok()?;
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        std::thread::sleep(Duration::from_millis(100));
                        if self.handler.is_finished() {
                            break;
                        }
                    }
                    if !self.handler.is_finished() {
                        warn!("[Can be safely ignored] File watching not finished yet.");
                    }
                })
                .join()
                .unwrap();
            }
            Some(())
        }
    }
}

pub use v1::*;
