//! Checks that a Python value can be lowered as a WIT type.
//!
//! The `Call` implementation lowers values with infallible methods, so a value
//! that does not match its WIT type would otherwise panic in the middle of
//! lowering. Checking the complete value first lets an import call raise a
//! Python exception before anything reaches the host, and lets an export report
//! which value is wrong.

use {
    super::{ERR_CONSTRUCTOR, OK_CONSTRUCTOR, OPTIONS, RECORDS, RESULTS, TUPLES, VARIANTS},
    crate::bindings::exports::exports::OptionKind,
    num_bigint::BigUint,
    pyo3::{
        Bound, PyAny, PyErr, PyResult, Python,
        exceptions::{PyOverflowError, PyTypeError, PyValueError},
        intern,
        types::{
            PyAnyMethods, PyBytes, PyDict, PyDictMethods, PyFloat, PyInt, PyList, PyListMethods,
            PyString, PyStringMethods, PyTuple, PyTupleMethods, PyTypeMethods,
        },
    },
    wit_dylib_ffi::Type,
};

/// Checks `value` against `ty`, naming the value `path` in any error.
pub fn check(
    py: Python<'_>,
    ty: Type,
    value: &Bound<'_, PyAny>,
    path: &mut String,
) -> PyResult<()> {
    match ty {
        Type::U8 => int::<u8>(value, "u8", path),
        Type::U16 => int::<u16>(value, "u16", path),
        Type::U32 => int::<u32>(value, "u32", path),
        Type::U64 => int::<u64>(value, "u64", path),
        Type::S8 => int::<i8>(value, "s8", path),
        Type::S16 => int::<i16>(value, "s16", path),
        Type::S32 => int::<i32>(value, "s32", path),
        Type::S64 => int::<i64>(value, "s64", path),
        Type::Bool => Ok(()),
        Type::F32 | Type::F64 => {
            if value.is_instance_of::<PyFloat>() || value.is_instance_of::<PyInt>() {
                value.extract::<f64>().map(drop).map_err(|_| {
                    PyOverflowError::new_err(format!(
                        "{path}: {} is out of range for a float",
                        repr(value)
                    ))
                })
            } else {
                Err(type_error("float", value, path))
            }
        }
        Type::Char => {
            let s = value
                .cast::<PyString>()
                .map_err(|_| type_error("char (str of length 1)", value, path))?;
            if s.to_cow()?.chars().count() == 1 {
                Ok(())
            } else {
                Err(PyValueError::new_err(format!(
                    "{path}: expected char, got a str of length {}",
                    s.len()?
                )))
            }
        }
        Type::String => {
            let s = value
                .cast::<PyString>()
                .map_err(|_| type_error("str", value, path))?;
            // Lone surrogates cannot be encoded as UTF-8.
            s.to_str().map(drop).map_err(|error| {
                let wrapped = PyValueError::new_err(format!("{path}: {}", error.value(py)));
                wrapped.set_cause(py, Some(error));
                wrapped
            })
        }
        Type::ErrorContext => Ok(()),
        Type::Record(ty) => {
            let record = &RECORDS.get().unwrap()[ty.index()];
            for (name, (_, field_ty)) in record.fields.iter().zip(ty.fields()) {
                let field = value
                    .getattr(name.as_str())
                    .map_err(|_| type_error(&format!("record `{}`", ty.name()), value, path))?;
                nested(path, &format!(".{name}"), |path| {
                    check(py, field_ty, &field, path)
                })?;
            }
            Ok(())
        }
        Type::Own(_) | Type::Borrow(_) | Type::Future(_) | Type::Stream(_) => {
            // Exported resources accept any object; imported handles must still
            // be live.
            let is_import = match ty {
                Type::Own(ty) | Type::Borrow(ty) => ty.new().is_none(),
                _ => true,
            };
            if is_import {
                let handle = value
                    .getattr(intern!(py, "handle"))
                    .and_then(|handle| handle.extract::<u32>())
                    .map_err(|_| type_error("a resource handle", value, path))?;
                if handle == 0 {
                    return Err(PyValueError::new_err(format!(
                        "{path}: the handle was already moved or dropped"
                    )));
                }
            }
            Ok(())
        }
        Type::Tuple(ty) => {
            let count = TUPLES.get().unwrap()[ty.index()].count;
            let tuple = value
                .cast::<PyTuple>()
                .map_err(|_| type_error(&format!("tuple of {count}"), value, path))?;
            if tuple.len() != count {
                return Err(PyValueError::new_err(format!(
                    "{path}: expected a tuple of {count}, got {}",
                    tuple.len()
                )));
            }
            for (index, element_ty) in ty.types().enumerate() {
                let element = tuple.get_item(index)?;
                nested(path, &format!("[{index}]"), |path| {
                    check(py, element_ty, &element, path)
                })?;
            }
            Ok(())
        }
        Type::Variant(ty) => {
            let variant = &VARIANTS.get().unwrap()[ty.index()];
            let discriminant = variant
                .types_to_discriminants
                .bind(py)
                .get_item(value.get_type())?
                .ok_or_else(|| {
                    type_error(&format!("a case of variant `{}`", ty.name()), value, path)
                })?
                .extract::<usize>()?;
            let (case_name, case_ty) = ty.cases().nth(discriminant).unwrap();
            match case_ty {
                Some(case_ty) if variant.cases[discriminant].has_payload => {
                    let payload = value.getattr(intern!(py, "value"))?;
                    nested(path, &format!("<{case_name}>"), |path| {
                        check(py, case_ty, &payload, path)
                    })
                }
                _ => Ok(()),
            }
        }
        Type::Flags(_) => value
            .getattr(intern!(py, "value"))
            .and_then(|bits| bits.extract::<BigUint>())
            .map(drop)
            .map_err(|_| type_error("flags", value, path)),
        Type::Enum(ty) => {
            let index = value
                .getattr(intern!(py, "value"))
                .and_then(|index| index.extract::<usize>())
                .map_err(|_| type_error(&format!("enum `{}`", ty.name()), value, path))?;
            if index < ty.names().len() {
                Ok(())
            } else {
                Err(PyValueError::new_err(format!(
                    "{path}: {index} is not a case of enum `{}`",
                    ty.name()
                )))
            }
        }
        Type::Option(ty) => {
            if value.is_none() {
                return Ok(());
            }
            let payload = match OPTIONS.get().unwrap()[ty.index()] {
                OptionKind::NonNesting => value.clone(),
                OptionKind::Nesting => value
                    .getattr(intern!(py, "value"))
                    .map_err(|_| type_error("None or Some", value, path))?,
            };
            nested(path, "?", |path| check(py, ty.ty(), &payload, path))
        }
        Type::Result(ty) => {
            let record = &RESULTS.get().unwrap()[ty.index()];
            let (name, payload_ty, has_payload) = if OK_CONSTRUCTOR
                .get()
                .unwrap()
                .bind(py)
                .eq(value.get_type())?
            {
                ("Ok", ty.ok(), record.has_ok)
            } else if ERR_CONSTRUCTOR
                .get()
                .unwrap()
                .bind(py)
                .eq(value.get_type())?
            {
                ("Err", ty.err(), record.has_err)
            } else {
                return Err(type_error("Ok or Err", value, path));
            };
            match payload_ty {
                Some(payload_ty) if has_payload => {
                    let payload = value.getattr(intern!(py, "value"))?;
                    nested(path, &format!("<{name}>"), |path| {
                        check(py, payload_ty, &payload, path)
                    })
                }
                _ => Ok(()),
            }
        }
        Type::List(ty) => {
            let element_ty = ty.ty();
            if let Type::U8 | Type::S8 = element_ty {
                return value
                    .cast::<PyBytes>()
                    .map(drop)
                    .map_err(|_| type_error("bytes", value, path));
            }
            let list = value
                .cast::<PyList>()
                .map_err(|_| type_error("list", value, path))?;
            for (index, element) in list.iter().enumerate() {
                nested(path, &format!("[{index}]"), |path| {
                    check(py, element_ty, &element, path)
                })?;
            }
            Ok(())
        }
        Type::FixedLengthList(ty) => {
            let list = value
                .cast::<PyList>()
                .map_err(|_| type_error(&format!("list of {}", ty.len()), value, path))?;
            if list.len() != ty.len() {
                return Err(PyValueError::new_err(format!(
                    "{path}: expected a list of {}, got {}",
                    ty.len(),
                    list.len()
                )));
            }
            for (index, element) in list.iter().enumerate() {
                nested(path, &format!("[{index}]"), |path| {
                    check(py, ty.ty(), &element, path)
                })?;
            }
            Ok(())
        }
        Type::Map(ty) => {
            let dict = value
                .cast::<PyDict>()
                .map_err(|_| type_error("dict", value, path))?;
            for (key, item) in dict.iter() {
                let label = key.repr()?.to_string();
                nested(path, &format!("[{label}] key"), |path| {
                    check(py, ty.key_type(), &key, path)
                })?;
                nested(path, &format!("[{label}]"), |path| {
                    check(py, ty.value_type(), &item, path)
                })?;
            }
            Ok(())
        }
        Type::Alias(ty) => check(py, ty.ty(), value, path),
    }
}

fn int<'py, T: for<'a> pyo3::FromPyObject<'a, 'py>>(
    value: &Bound<'py, PyAny>,
    name: &str,
    path: &str,
) -> PyResult<()> {
    if !value.is_instance_of::<PyInt>() {
        return Err(type_error(name, value, path));
    }
    value.extract::<T>().map(drop).map_err(|_| {
        PyOverflowError::new_err(format!(
            "{path}: {} is out of range for {name}",
            repr(value)
        ))
    })
}

fn nested(
    path: &mut String,
    suffix: &str,
    f: impl FnOnce(&mut String) -> PyResult<()>,
) -> PyResult<()> {
    let len = path.len();
    path.push_str(suffix);
    let result = f(path);
    path.truncate(len);
    result
}

fn type_error(expected: &str, value: &Bound<'_, PyAny>, path: &str) -> PyErr {
    let actual = value
        .get_type()
        .name()
        .map(|name| name.to_string())
        .unwrap_or_else(|_| "?".into());
    PyTypeError::new_err(format!("{path}: expected {expected}, got {actual}"))
}

fn repr(value: &Bound<'_, PyAny>) -> String {
    value
        .repr()
        .map(|repr| repr.to_string())
        .unwrap_or_else(|_| "?".into())
}
