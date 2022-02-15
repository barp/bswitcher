use async_native_tls;
use async_std::sync::{Arc, Mutex};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use bswitch::api::{discover_central_units, CombinedError, UnitItemOperation};
use bswitch::protocol::*;

#[pyclass(name = "CuClient")]
pub struct PyCuClient(Arc<Mutex<CuClient>>);

#[pyclass]
#[derive(Clone)]
pub struct UnitItem {
    #[pyo3(get)]
    pub zone: String,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub unit_id: i32,
    #[pyo3(get)]
    pub value: i32,
    #[pyo3(get)]
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
            let identity = async_native_tls::Identity::from_pkcs12(&certificate, "1234")
                .map_err(|e| CombinedError::from(e))?;
            let client = CuClient::new(&ip, port, identity)
                .await
                .map_err(|e| CombinedError::from(e))?;
            Ok(PyCuClient(Arc::new(Mutex::new(client))))
        })
    }

    pub fn request<'p>(&mut self, py: Python<'p>, request: String) -> PyResult<&'p PyAny> {
        let client = Arc::clone(&self.0);
        pyo3_asyncio::async_std::future_into_py(py, async move {
            Ok(client
                .lock()
                .await
                .request(&request)
                .await
                .map_err(|e| CombinedError::from(e))?)
        })
    }

    pub fn get_all_items<'p>(&mut self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let client = Arc::clone(&self.0);
        pyo3_asyncio::async_std::future_into_py(py, async move {
            let resp = client
                .lock()
                .await
                .get_all()
                .await
                .map_err(|e| CombinedError::from(e))?;
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
                Err(e) => return Err(e.into()),
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

#[pyfunction]
fn discover_central_unit(py: Python) -> PyResult<&PyAny> {
    pyo3_asyncio::async_std::future_into_py(py, async { Ok(discover_central_units(true).await?) })
}

#[pymodule]
fn pybswitch(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyCuClient>()?;
    m.add_function(wrap_pyfunction!(discover_central_unit, m)?)?;
    Ok(())
}
