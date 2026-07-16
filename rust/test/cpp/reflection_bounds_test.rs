// Protocol Buffers - Google's data interchange format
// Copyright 2024 Google LLC.  All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#[cfg(not(lite_runtime))]
#[cfg(test)]
mod reflection_bound_test {
    use protobuf_cpp_export as protobuf;

    #[allow(dead_code)]
    // Proves that any generic message bounded by WithReflection automatically inherits access to
    // C++ MessageDescriptorInterop methods when compiled under cpp_kernel.
    pub fn print_to_text_format_example<T: protobuf::WithReflection>(_msg: &T) -> String {
        let _raw_desc = T::__unstable_get_descriptor();
        // ... call C++ TextFormat FFI ...
        // Return a dummy value to make the compiler happy.
        String::new()
    }
}
