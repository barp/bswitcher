use async_native_tls;
use async_std::sync::{Arc, Mutex};
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;

use bswitch::api::{CombinedError, UnitItemOperation};
use bswitch::protocol::*;

pub struct CombinedErrorWrapper(CombinedError);

impl From<CombinedErrorWrapper> for PyErr {
    fn from(err: CombinedErrorWrapper) -> Self {
        match err.0 {
            CombinedError::AsyncTlsError(err) => PyOSError::new_err(err.to_string()),
            _ => PyOSError::new_err("rust error"),
        }
    }
}

#[pyclass(name = "CuClient")]
pub struct PyCuClient(Arc<Mutex<CuClient>>);

#[pyclass]
#[derive(Clone)]
pub struct UnitItem {
    pub zone: String,
    pub name: String,
    pub unit_id: i32,
    pub value: i32,
    pub unit_type: i32,
}

#[pymethods]
impl UnitItem {
    pub fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "UnitItem<name: {}, id: {}, value: {}, type: {}>",
            self.name, self.unit_id, self.value, self.unit_type
        ))
    }

    pub fn is_on(&self) -> bool {
        self.value == 100
    }
}

impl UnitItem {
    pub fn with_value(mut self, value: i32) -> Self {
        self.value = value;
        return self;
    }
}

#[pymethods]
impl PyCuClient {
    #[staticmethod]
    pub fn new(py: Python, ip: String, port: u32, certificate: Vec<u8>) -> PyResult<&PyAny> {
        pyo3_asyncio::async_std::future_into_py(py, async move {
            let identity = match async_native_tls::Identity::from_pkcs12(&certificate, "1234") {
                Ok(v) => v,
                Err(e) => return Err(CombinedErrorWrapper(CombinedError::AsyncTlsError(e)).into()),
            };
            let client = match CuClient::new(&ip, port, identity).await {
                Ok(c) => c,
                Err(e) => return Err(CombinedErrorWrapper(e).into()),
            };
            Ok(PyCuClient(Arc::new(Mutex::new(client))))
        })
    }

    pub fn request<'p>(&mut self, py: Python<'p>, request: String) -> PyResult<&'p PyAny> {
        let client = Arc::clone(&self.0);
        pyo3_asyncio::async_std::future_into_py(py, async move {
            Ok(match client.lock().await.request(&request).await {
                Ok(v) => v,
                Err(e) => return Err(CombinedErrorWrapper(e).into()),
            })
        })
    }

    pub fn get_all_items<'p>(&mut self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let client = Arc::clone(&self.0);
        pyo3_asyncio::async_std::future_into_py(py, async move {
            let resp = match client.lock().await.get_all().await {
                Ok(v) => v,
                Err(e) => return Err(CombinedErrorWrapper(e).into()),
            };
            let mut result: Vec<UnitItem> = Vec::new();
            let places = match resp.place {
                Some(v) => v,
                None => return Ok(result),
            };
            for zone in &places.zones {
                for item in &zone.items {
                    result.push(UnitItem {
                        zone: zone.name.to_owned(),
                        name: item.name.to_owned(),
                        unit_id: item.unit_id,
                        value: item.value,
                        unit_type: item.unit_type,
                    })
                }
            }
            Ok(result)
        })
    }

    pub fn change_state<'p>(
        &mut self,
        py: Python<'p>,
        item: UnitItem,
        new_state: i32,
    ) -> PyResult<&'p PyAny> {
        let client = Arc::clone(&self.0);
        pyo3_asyncio::async_std::future_into_py(py, async move {
            match client
                .lock()
                .await
                .unit_operation(&UnitItemOperation {
                    new_state,
                    unit_type: item.unit_type,
                    unit_id: item.unit_id,
                })
                .await
            {
                Ok(_) => Ok(item.clone().with_value(new_state)),
                Err(e) => return Err(CombinedErrorWrapper(e).into()),
            }
        })
    }

    pub fn turn_on<'p>(&mut self, py: Python<'p>, item: UnitItem) -> PyResult<&'p PyAny> {
        self.change_state(py, item, 100)
    }

    pub fn turn_off<'p>(&mut self, py: Python<'p>, item: UnitItem) -> PyResult<&'p PyAny> {
        self.change_state(py, item, 0)
    }
}

#[pymodule]
fn pybswitch(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyCuClient>()?;
    Ok(())
}
