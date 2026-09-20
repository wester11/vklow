use keyring::Entry;

pub trait SecretStore: Send + Sync {
    fn set(&self, key: &str, secret: &str) -> Result<(), String>;
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    fn delete(&self, key: &str) -> Result<(), String>;
}

pub struct WindowsSecretStore;
impl WindowsSecretStore {
    pub fn new() -> Self {
        Self
    }
}
impl SecretStore for WindowsSecretStore {
    fn set(&self, key: &str, secret: &str) -> Result<(), String> {
        Entry::new("VOID Desktop", key)
            .map_err(|_| "Не удалось открыть Windows secure storage")?
            .set_password(secret)
            .map_err(|_| "Не удалось сохранить secret в Windows secure storage".to_owned())
    }
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        match Entry::new("VOID Desktop", key)
            .map_err(|_| "Не удалось открыть Windows secure storage")?
            .get_password()
        {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err("Не удалось получить secret из Windows secure storage".into()),
        }
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        match Entry::new("VOID Desktop", key)
            .map_err(|_| "Не удалось открыть Windows secure storage")?
            .delete_credential()
        {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err("Не удалось удалить secret из Windows secure storage".into()),
        }
    }
}

pub fn subscription_url_key(id: &str) -> String {
    format!("subscription:{id}:url")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex};
    struct MemoryStore(Mutex<HashMap<String, String>>);
    impl SecretStore for MemoryStore {
        fn set(&self, key: &str, secret: &str) -> Result<(), String> {
            self.0.lock().unwrap().insert(key.into(), secret.into());
            Ok(())
        }
        fn get(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }
    #[test]
    fn store_contract_set_get_delete() {
        let store = MemoryStore(Mutex::new(HashMap::new()));
        store
            .set("subscription:id:url", "https://example.test/?token=secret")
            .unwrap();
        assert!(store.get("subscription:id:url").unwrap().is_some());
        store.delete("subscription:id:url").unwrap();
        assert!(store.get("subscription:id:url").unwrap().is_none());
    }
}
