// Copyright 2017 WhiteHat Security
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

package com.whitehatsec.scout;

public enum Rating {

    Note(1, "Note"),
    Low(2, "Low"),
    Medium(3, "Medium"),
    High(4, "High"),
    Critical(5, "Critical");

    private int risk;
    private String displayName;

    Rating(int risk, String displayName) {
        this.risk = risk;
        this.displayName = displayName;
    }

    int getRisk() {
        return risk;
    }

    String getDisplayName() {
        return displayName;
    }

    static Rating fromRisk(int risk) {
        for (Rating r : Rating.values()) {
            if (r.risk == risk) {
                return r;
            }
        }
        return null;
    }

    static Rating fromText(String text) {
        for (Rating r : Rating.values()) {
            if (r.displayName.equalsIgnoreCase(text)) {
                return r;
            }
        }
        return null;
    }
}
