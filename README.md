# AEALSF – Adaptive Edge-Assisted Lightweight Security Framework for Resource-Constrained IoT Devices

**Project:** AEALSF – Adaptive Edge-Assisted Lightweight Security Framework  
**Team:** Team 12  
**Team Members:** B. Nithin Ramgopal (`CS23B2050`) | N. Ravi Tejesh (`CS23B2051`) | N. Durga Prasad (`CS23B2052`)

---

## 1. Project Overview

The **Adaptive Edge-Assisted Lightweight Security Framework (AEALSF)** is a research-oriented security framework designed for resource-constrained Internet of Things (IoT) devices.

The framework combines adaptive task scheduling, edge-assisted execution, lightweight cryptographic mechanisms, and blockchain-inspired integrity verification to provide security while considering the computational and resource limitations of IoT devices.

AEALSF uses an adaptive decision engine to evaluate resource availability and execution costs before determining whether a task should be processed locally or delegated to an edge node.

The project provides a software-based experimental environment for evaluating the framework's performance, security mechanisms, scalability, and resource utilization.

## 2. Key Features

- **Adaptive Decision Engine:** Evaluates resource availability and execution costs to determine task execution strategies.
- **Edge-Assisted Execution:** Supports task delegation and execution through edge nodes.
- **Lightweight Cryptography:** Implements encryption, key management, and cryptographic verification.
- **NIZK Authentication:** Provides a non-interactive zero-knowledge authentication mechanism.
- **Homomorphic Encryption:** Includes homomorphic encryption functionality for privacy-preserving operations.
- **Blockchain-Based Integrity:** Implements transaction management, integrity verification, and a DVRC consensus simulation.
- **Device Management:** Handles device identities, resource monitoring, and local security operations.
- **Performance Monitoring:** Collects execution, resource, and performance metrics.
- **Experimental Evaluation:** Includes benchmarking, scalability testing, calibration, and security evaluation.

## 3. System Architecture

The framework is organized into the following major components:

| Component       | Responsibility                                                                  |
| --------------- | ------------------------------------------------------------------------------- |
| Adaptive Engine | Resource analysis, cost estimation, policy management, and execution scheduling |
| API             | Exposes framework functionality through API endpoints                           |
| Blockchain      | Transaction management, consensus simulation, and integrity verification        |
| Cryptography    | Encryption, key management, NIZK authentication, and verification               |
| Device          | Device identity, management, resource monitoring, and local security            |
| Edge            | Edge authentication, task execution, monitoring, and failover                   |
| Monitoring      | Performance metrics, energy estimation, and logging                             |
| Smart Contracts | Solidity contracts and Circom circuit implementation                            |
| Experiments     | Benchmarking, calibration, scalability, and security evaluation                 |
| Tests           | Unit, integration, and security-related test cases                              |

### High-Level Execution Flow

1. An IoT device generates a task.
2. The adaptive engine evaluates device resources and execution costs.
3. The decision engine selects an appropriate execution strategy.
4. The task is processed locally or delegated to an edge node.
5. Security mechanisms authenticate and verify the relevant operations.
6. Blockchain-related components maintain transaction and integrity information.
7. Monitoring components collect performance and resource metrics.
8. Experimental modules evaluate the framework using collected results.

## 4. Project Directory Structure

```text
Team_12_Final_Submission/
│
├── README.md
├── .env.example
├── .gitignore
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── cli.py
│
├── adaptive_engine/
│   ├── cost_estimator.py
│   ├── decision_engine.py
│   ├── execution_scheduler.py
│   ├── policy_manager.py
│   └── resource_analyzer.py
│
├── api/
│   ├── main.py
│   ├── routes/
│   └── schemas/
│
├── blockchain/
│
├── config/
│
├── cryptography/
│
├── device/
│
├── edge/
│
├── monitoring/
│
├── smart_contracts/
│   ├── Algorithm1.circom
│   ├── DeviceRegistry.sol
│   ├── SecurityManager.sol
│   ├── TaskManagement.sol
│   ├── c_sdk_generator.py
│   └── generated_c_sdk/
│
├── experiments/
│
├── tests/
│
├── docs/
│   ├── Architecture.md
│   ├── Experimental_Setup.md
│   ├── Experimental_results.md
│   ├── Implementation.md
│   ├── Limitations.md
│   ├── Methodology.md
│   ├── Readme.md
│   └── Results_and_Analysis.md
│
└── results/
    ├── benchmark_results.json
    ├── benchmark_summary.csv
    ├── raw_trials.csv
    ├── raw_trials.json
    ├── statistical_analysis.csv
    ├── sensitivity_analysis.csv
    ├── validation_pipeline_report.json
    ├── figures/
    └── tables/
```

The directory listing above highlights the major project components. Retain the complete source files and generated experimental outputs in their respective directories.

## 5. Technologies Used

- **Programming Language:** Python 3.11
- **API Framework:** FastAPI
- **Data Validation:** Pydantic
- **Cryptographic Operations:** Python Cryptography Library
- **Numerical Computing:** NumPy and SciPy
- **Symbolic Computation:** SymPy
- **Data Analysis:** Pandas
- **Visualization:** Matplotlib
- **Smart Contracts:** Solidity
- **Zero-Knowledge Circuit:** Circom
- **Containerization:** Docker and Docker Compose
- **Testing:** Python unittest framework

## 6. System Requirements

Recommended environment:

- Python 3.11
- pip package manager
- Docker Desktop (for containerized execution)
- Git (optional, for version control)
- Windows, Linux, or macOS

Some cryptographic acceleration components may be platform-dependent. The supplied `_secp256k1_accel.so` file is intended for compatible Linux environments. On other platforms, the Python fallback implementation may be used.

## 7. Installation and Setup

### Step 1: Extract the Project

Extract the submitted project ZIP file.

Open a terminal or PowerShell window inside the project directory.

### Step 2: Create a Virtual Environment

```bash
python -m venv venv
```

Activate the environment.

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Copy `.env.example` to `.env` if environment-specific configuration is required.

Update the values according to the local environment.

Do not commit passwords, private keys, API credentials, or other sensitive information.

## 8. Running the Project

The project provides a command-line interface through `cli.py`.

### Run the Demonstration Workflow

```bash
python cli.py demo-workflow
```

This command runs the framework's demonstration workflow.

### Run Unit and Integration Tests

```bash
python cli.py test
```

Alternatively, run the test suite directly:

```bash
python -m unittest discover -s tests -v
```

### Run Benchmark Experiments

```bash
python cli.py benchmark
```

This executes the benchmark workflow and generates experimental figures and related outputs in the results directory.

### Run Weight Calibration

```bash
python cli.py calibrate
```

### Run DDoS and Entropy Evaluation

```bash
python cli.py ddos-eval
```

### Generate the C SDK

```bash
python cli.py generate-c-sdk
```

## 9. Running the API

Start the FastAPI application using:

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

After starting the application, access the API documentation at:

```text
http://127.0.0.1:8000/docs
```

The API provides endpoints for the framework's supported device, edge, task, blockchain, authentication, and monitoring operations.

## 10. Docker Deployment

The project includes a `Dockerfile` and `docker-compose.yml` for containerized execution.

Build and start the configured services:

```bash
docker compose up --build
```

To stop the services:

```bash
docker compose down
```

**Important:** The supplied Docker Compose blockchain services are Python-based blockchain client processes used for simulation. They should not be interpreted as a production deployment of actual FISCO BCOS blockchain nodes.

Review the Compose configuration before claiming that it reproduces the complete experimental topology. In particular, ensure that the configured edge-node count matches the topology described in the experimental setup.

## 11. Experimental Evaluation

The project includes experimental modules for evaluating the framework.

| Experiment                 | Purpose                              |
| -------------------------- | ------------------------------------ |
| `baseline.py`              | Baseline performance evaluation      |
| `benchmark.py`             | Benchmark execution                  |
| `calibrate_weights.py`     | Adaptive decision-weight calibration |
| `ddos_and_entropy_eval.py` | Security and entropy evaluation      |
| `proposed_framework.py`    | Proposed framework evaluation        |
| `scalability_test.py`      | Scalability evaluation               |
| `validate_pipeline.py`     | Experimental pipeline validation     |
| `generate_results.py`      | Result generation                    |
| `generate_docs.py`         | Documentation generation             |

The results directory contains experimental data, statistical analysis, validation reports, figures, and tables.

These outputs are retained to support research reproducibility and result verification.

## 12. Experimental Environment and Limitations

**Important research clarification:**

AEALSF is a simulation-based research implementation.

The experimental evaluation uses a software-based environment rather than a physical IoT hardware deployment.

The documented experimental setup distinguishes between:

- Measurements collected on the host execution environment.
- Simulated IoT device, edge, and validator resource outputs.
- Resource profiles parameterized against the documented Fibocom L610-CN device profile.
- Energy estimates calculated using an analytical LTE Cat.1 energy model.

No physical Raspberry Pi, ESP32, Fibocom L610-CN device, or hardware power meter was used for the reported experiments.

Consequently, simulated resource values and analytical energy estimates should not be presented as direct physical hardware measurements.

Other implementation limitations and experimental assumptions are described in:

- `docs/Limitations.md`
- `docs/Experimental_Setup.md`
- `docs/Methodology.md`

## 13. Test and Validation

The project contains test modules covering:

- Adaptive engine functionality
- Benchmark integrity
- Blockchain operations
- Calibration and DDoS evaluation
- Device management
- Edge execution
- Homomorphic encryption
- Instrumentation and corrective mechanisms
- Integration workflows
- NIZK authentication
- Security functionality

Run the complete test suite before final submission:

```bash
python -m unittest discover -s tests -v
```

Record the actual test results from the final execution environment. Do not report a test as passing unless it has been successfully executed.

## 14. Research Documentation

Additional technical and research documentation is available under the `docs/` directory.

| Document                  | Description                                |
| ------------------------- | ------------------------------------------ |
| `Architecture.md`         | Framework architecture                     |
| `Experimental_Setup.md`   | Experimental environment and configuration |
| `Experimental_results.md` | Experimental results                       |
| `Implementation.md`       | Implementation details                     |
| `Limitations.md`          | Known limitations                          |
| `Methodology.md`          | Research methodology                       |
| `Readme.md`               | Existing project documentation             |
| `Results_and_Analysis.md` | Result interpretation and analysis         |

## 15. Reproducibility

To reproduce the documented software experiments:

1. Install Python 3.11.
2. Create and activate a virtual environment.
3. Install the dependencies from `requirements.txt`.
4. Configure the required environment variables.
5. Run the test suite.
6. Execute the relevant experiment through `cli.py`.
7. Inspect the generated outputs in `results/`.
8. Compare the generated data with the supplied experimental records.

For accurate comparisons, use the experimental configuration, seeds, and assumptions documented in the research materials.

## 16. Security and Configuration Notes

- Never include actual `.env` files containing secrets in the submission.
- Use `.env.example` to document required configuration variables.
- Do not distribute private keys or credentials.
- Retain the cryptographic source code and required generated SDK files.
- Review platform compatibility before using compiled acceleration libraries.
- Treat the supplied blockchain deployment as a simulation unless a real blockchain deployment is independently configured and verified.

## 17. Final Submission Contents

The final submission should contain:

- Complete Python source code.
- API and configuration modules.
- Adaptive engine, device, and edge components.
- Cryptographic and blockchain simulation modules.
- Smart contracts and required generated C SDK files.
- Experimental scripts.
- Complete test suite.
- Experimental raw data and processed results.
- Figures and tables.
- Research documentation.
- Dependency and Docker configuration files.
- This root-level README.
- The final IEEE research paper as a separate submission file, if required by the institution.

## 18. Conclusion

AEALSF presents a simulation-based implementation of an adaptive edge-assisted security framework for resource-constrained IoT devices.

By integrating adaptive execution decisions, edge-assisted processing, cryptographic authentication, and blockchain-inspired integrity verification, the project provides an experimental platform for studying security and resource-aware task execution in IoT environments.

The source code, experimental scripts, validation outputs, and documentation are organized to support inspection, execution, and reproducibility of the research implementation.

---

**Team 12 – AEALSF Research Project**
#   A E A L S F - A d a p t i v e - E d g e - A s s i s t e d - L i g h t w e i g h t - S e c u r i t y - F r a m e w o r k . 
 
 
