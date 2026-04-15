use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativeEntry {
    pub original: String,
    pub alternatives: String,
    pub notes: String,
    pub category: String,
}

pub struct AlternativesDb {
    entries: Vec<AlternativeEntry>,
}

impl AlternativesDb {
    pub fn load() -> anyhow::Result<Self> {
        let path = Self::get_db_path();

        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let entries: Vec<AlternativeEntry> = serde_json::from_str(&content)?;
            Ok(Self { entries })
        } else {
            let entries = Self::default_entries();
            let content = serde_json::to_string_pretty(&entries)?;
            fs::write(&path, content)?;
            Ok(Self { entries })
        }
    }

    pub fn search(&self, query: &str) -> Vec<&AlternativeEntry> {
        let query_lower = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.original.to_lowercase().contains(&query_lower)
                    || e.alternatives.to_lowercase().contains(&query_lower)
                    || e.category.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    #[allow(dead_code)]
    pub fn list_all(&self) -> &[AlternativeEntry] {
        &self.entries
    }

    fn default_entries() -> Vec<AlternativeEntry> {
        vec![
            AlternativeEntry {
                original: "Chrome".to_string(),
                alternatives: "Brave, Firefox, LibreWolf".to_string(),
                notes:
                    "LibreWolf is a privacy-focused Firefox fork with telemetry disabled by default"
                        .to_string(),
                category: "Browser".to_string(),
            },
            AlternativeEntry {
                original: "VS Code".to_string(),
                alternatives: "VSCodium, Neovim, Helix, Zed".to_string(),
                notes: "VSCodium is VS Code without Microsoft telemetry".to_string(),
                category: "Editor".to_string(),
            },
            AlternativeEntry {
                original: "Slack".to_string(),
                alternatives: "Element, Mattermost, Revolt".to_string(),
                notes: "Element uses Matrix protocol, fully decentralized and E2E encrypted"
                    .to_string(),
                category: "Communication".to_string(),
            },
            AlternativeEntry {
                original: "Discord".to_string(),
                alternatives: "Element, Revolt, TeamSpeak".to_string(),
                notes: "Revolt is an open-source Discord alternative with similar UI".to_string(),
                category: "Communication".to_string(),
            },
            AlternativeEntry {
                original: "Teams".to_string(),
                alternatives: "Jitsi Meet, Element, BigBlueButton".to_string(),
                notes: "Jitsi Meet is fully open-source with no account required".to_string(),
                category: "Communication".to_string(),
            },
            AlternativeEntry {
                original: "Spotify".to_string(),
                alternatives: "Spotifyd, MusicBee, Audacious".to_string(),
                notes: "Spotifyd is a lightweight Spotify client with minimal telemetry"
                    .to_string(),
                category: "Music".to_string(),
            },
            AlternativeEntry {
                original: "Steam".to_string(),
                alternatives: "Heroic Games Launcher, Lutris, GOG Galaxy".to_string(),
                notes: "Heroic supports Epic and GOG games with minimal telemetry".to_string(),
                category: "Gaming".to_string(),
            },
            AlternativeEntry {
                original: "OneDrive".to_string(),
                alternatives: "Syncthing, Nextcloud, Seafile".to_string(),
                notes: "Syncthing is fully decentralized with no central server".to_string(),
                category: "Cloud Storage".to_string(),
            },
            AlternativeEntry {
                original: "Dropbox".to_string(),
                alternatives: "Syncthing, Nextcloud, Resilio Sync".to_string(),
                notes: "Nextcloud provides self-hosted cloud storage with full control".to_string(),
                category: "Cloud Storage".to_string(),
            },
            AlternativeEntry {
                original: "Zoom".to_string(),
                alternatives: "Jitsi Meet, BigBlueButton, Signal".to_string(),
                notes: "Signal provides E2E encrypted video calls with minimal data collection"
                    .to_string(),
                category: "Communication".to_string(),
            },
            AlternativeEntry {
                original: "Adobe Reader".to_string(),
                alternatives: "SumatraPDF, Okular, MuPDF".to_string(),
                notes: "SumatraPDF is lightweight with no telemetry or cloud features".to_string(),
                category: "Document Viewer".to_string(),
            },
            AlternativeEntry {
                original: "Microsoft Office".to_string(),
                alternatives: "LibreOffice, OnlyOffice, WPS Office".to_string(),
                notes: "LibreOffice is fully open-source with no telemetry".to_string(),
                category: "Productivity".to_string(),
            },
            AlternativeEntry {
                original: "Windows Defender".to_string(),
                alternatives: "ClamAV, Sophos, ESET".to_string(),
                notes: "ClamAV is open-source antivirus with no cloud telemetry".to_string(),
                category: "Security".to_string(),
            },
            AlternativeEntry {
                original: "Google Analytics".to_string(),
                alternatives: "Plausible, Fathom, Matomo".to_string(),
                notes: "Plausible is privacy-friendly analytics that doesn't use cookies"
                    .to_string(),
                category: "Analytics".to_string(),
            },
        ]
    }

    fn get_db_path() -> PathBuf {
        let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("/etc"));
        config_dir.join("corpaudit").join("alternatives.json")
    }
}
