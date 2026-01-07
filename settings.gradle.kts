/*
 * Copyright 2026 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik find details in the "Readme" file.
 */

plugins {
  // For setting up refreshVersions plugin see
  // https://jmfayard.github.io/refreshVersions/
  id("de.fayard.refreshVersions") version "0.60.6"

  // Apply the foojay-resolver plugin to allow automatic download of JDKs
  id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

// begin dependencyResolutionManagement  . . . . . . . . . . . . . . . . . . . .
dependencyResolutionManagement {
  repositories {
    mavenCentral() // for all the public libraries
  }
} // end dependencyResolutionManagement ________________________________________

rootProject.name = "mwe-elcSessionkey4SM"

include("app")
