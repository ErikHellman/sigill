//! Enumerations shared by every crate. Each maps to the text stored in SQLite.

use serde::{Deserialize, Serialize};

macro_rules! text_enum {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl std::str::FromStr for $name {
            type Err = UnknownVariant;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($text => Ok($name::$variant),)+
                    other => Err(UnknownVariant(other.to_string())),
                }
            }
        }
    };
}

#[derive(Debug, thiserror::Error)]
#[error("unknown value {0:?}")]
pub struct UnknownVariant(pub String);

text_enum!(
    /// Mail stream: separate IPs, subdomains and worker slots.
    Stream { Transactional => "transactional", Broadcast => "broadcast" }
);

text_enum!(
    /// State of one delivery (one recipient of one message).
    DeliveryStatus {
        Queued => "queued",
        Sending => "sending",
        Sent => "sent",
        Deferred => "deferred",
        Bounced => "bounced",
        Failed => "failed",
        Suppressed => "suppressed",
    }
);

impl DeliveryStatus {
    /// No further attempts will be made.
    pub fn is_final(self) -> bool {
        matches!(
            self,
            DeliveryStatus::Sent
                | DeliveryStatus::Bounced
                | DeliveryStatus::Failed
                | DeliveryStatus::Suppressed
        )
    }
}

text_enum!(
    /// Kind of row in `delivery_events`.
    EventKind {
        Queued => "queued",
        Sent => "sent",
        Deferred => "deferred",
        Bounced => "bounced",
        Complained => "complained",
        Failed => "failed",
        Suppressed => "suppressed",
        Unsubscribed => "unsubscribed",
    }
);

impl EventKind {
    /// Name of the webhook event sent to apps, if this kind is reported.
    pub fn webhook_name(self) -> Option<&'static str> {
        match self {
            EventKind::Sent => Some("delivered"),
            EventKind::Deferred => Some("deferred"),
            EventKind::Bounced => Some("bounced"),
            EventKind::Complained => Some("complained"),
            EventKind::Failed => Some("failed"),
            EventKind::Unsubscribed => Some("unsubscribed"),
            EventKind::Queued | EventKind::Suppressed => None,
        }
    }
}

text_enum!(
    SuppressionReason {
        HardBounce => "hard_bounce",
        SoftBounce => "soft_bounce",
        Complaint => "complaint",
        Unsubscribe => "unsubscribe",
        Manual => "manual",
    }
);

text_enum!(
    /// `all` blocks every stream; `broadcast` blocks only broadcast mail.
    SuppressionScope { All => "all", Broadcast => "broadcast" }
);

impl SuppressionScope {
    /// Does a suppression with this scope block mail on `stream`?
    pub fn blocks(self, stream: Stream) -> bool {
        match self {
            SuppressionScope::All => true,
            SuppressionScope::Broadcast => stream == Stream::Broadcast,
        }
    }
}

text_enum!(
    BroadcastStatus {
        Draft => "draft",
        Scheduled => "scheduled",
        Sending => "sending",
        Finished => "finished",
        Cancelled => "cancelled",
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_text() {
        for s in DeliveryStatus::ALL {
            assert_eq!(s.as_str().parse::<DeliveryStatus>().unwrap(), *s);
        }
        assert!("nope".parse::<Stream>().is_err());
        assert_eq!(EventKind::Sent.webhook_name(), Some("delivered"));
        assert!(SuppressionScope::Broadcast.blocks(Stream::Broadcast));
        assert!(!SuppressionScope::Broadcast.blocks(Stream::Transactional));
    }
}
