// Copyright 2025 The MWC Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::tor::arti;

pub struct ArtiRegistrator {
	name: String,
}

impl ArtiRegistrator {
	fn new(name: String) -> Self {
		arti::register_arti_active_object(name.clone());
		ArtiRegistrator { name }
	}
}

impl Drop for ArtiRegistrator {
	fn drop(&mut self) {
		arti::unregister_arti_active_object(&self.name);
	}
}

pub struct ArtiTrackedData<S> {
	pub stream: S,
	regist: ArtiRegistrator,
}

impl<S> ArtiTrackedData<S> {
	pub fn new(stream: S, name: String) -> Self {
		ArtiTrackedData {
			stream,
			regist: ArtiRegistrator::new(name),
		}
	}

	pub fn get_name(&self) -> String {
		self.regist.name.clone()
	}
}
