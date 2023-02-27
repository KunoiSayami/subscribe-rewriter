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
            let mut watcher = notify::recommended_watcher(move |res| match res {
                Ok(event) => {
                    if Self::decide(event) {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_io()
                            .build()
                            .unwrap()
                            .block_on(Self::send_event(sender.clone()));
                    }
                }
                Err(e) => {
                    error!(
                        "[Can be safely ignored] Got error while watching file {:?}",
                        e
                    )
                }
            })
            .map_err(|e| error!("[Can be safely ignored] Can't start watcher {:?}", e))
            .ok()?;

            let path = PathBuf::from(file);

            watcher
                .watch(&path, RecursiveMode::NonRecursive)
                .map_err(|e| error!("[Can be safely ignored] Unable to watch file: {:?}", e))
                .ok()?;

            stop_signal_channel
                .recv()
                .map_err(|e| {
                    error!(
                        "[Can be safely ignored] Got error while poll oneshot event: {:?}",
                        e
                    )
                })
                .ok();

            watcher
                .unwatch(&path)
                .map_err(|e| error!("[Can be safely ignored] Unable to unwatch file: {:?}", e))
                .ok()?;

            debug!("File watcher exited!");
            Some(())
        }

        fn decide(event: Event) -> bool {
            if let notify::EventKind::Access(notify::event::AccessKind::Close(
                notify::event::AccessMode::Write,
            )) = event.kind
            {
                return true;
            }
            event.need_rescan()
        }

        async fn send_event(sender: tokio::sync::mpsc::Sender<UpdateConfigureEvent>) -> Option<()> {
            sender
                .send(UpdateConfigureEvent::NeedUpdate)
                .await
                .map_err(|_| {
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
                    .map_err(|e| {
                        error!(
                "[Can be safely ignored] Unable send terminate signal to file watcher thread: {:?}",
                e
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
