use async_native_tls;
use async_std::future::Future;
use async_std::sync::{Arc, Mutex};
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;

use bswitch::api::CombinedError;
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

#[pyclass]
pub struct PyCuClient(Arc<Mutex<CuClient>>);

#[pymethods]
impl PyCuClient {
    pub fn request<'p>(&mut self, py: Python<'p>, request: String) -> PyResult<&'p PyAny> {
        let client = Arc::clone(&self.0);
        pyo3_asyncio::async_std::future_into_py(py, async move {
            Ok(match client.lock().await.request(&request).await {
                Ok(v) => v,
                Err(e) => return Err(CombinedErrorWrapper(e).into()),
            })
        })
    }
}

#[pyfunction]
pub fn create_cuclient(
    py: Python,
    ip: String,
    port: u32,
    certificate: Vec<u8>,
) -> PyResult<&PyAny> {
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

#[pymodule]
fn pybswitch(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyCuClient>()?;
    m.add_function(wrap_pyfunction!(create_cuclient, m)?)?;
    Ok(())
}
