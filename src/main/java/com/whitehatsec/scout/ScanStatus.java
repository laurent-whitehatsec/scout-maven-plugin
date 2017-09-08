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

public enum ScanStatus {
    Initialized("initialized", null),
    Queued("queued", "Artifact received"),
    ScanInitializing("scan_initializing", "Initializing scan"),
    ScanRunning("scan_running", "Scan in progress"),
    ScanSuccess("scan_success", "Scan complete"),
    ScanFailed("scan_failed", "Scan failure"),
    ProcessingResults("processing_results", "Processing scan results"),
    Complete("complete", "Complete", true, true),
    Failed("failed", "Failes", true, false),
    Cancelled("cancelled", "Scan aborted", true, false),
    SystemCancelled("system_cancelled", "Scan automatically cancelled", true, false),
    CancelledScanConflict("cancelled_scan_conflict", "Scan aborted by triggering a new scan", true, false);

    private String status;
    private boolean isComplete;
    private boolean isSuccess;
    private String displayName;

    ScanStatus(String status, String displayName) {
        this(status, displayName, false, false);
    }

    ScanStatus(String status, String displayName, boolean isComplete, boolean isSuccess) {
        this.status = status;
        this.isComplete = isComplete;
        this.isSuccess = isSuccess;
        this.displayName = displayName;
    }

    public boolean isComplete() {
        return this.isComplete;
    }

    public boolean isSuccess() {
        return this.isSuccess;
    }

    public String displayName() {
        return this.displayName;
    }

    public static ScanStatus fromStatus(String status) {
        for (ScanStatus s : ScanStatus.values()) {
            if (s.status.equalsIgnoreCase(status)) {
                return s;
            }
        }
        return null;
    }
}
