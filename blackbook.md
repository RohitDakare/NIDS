**(All the text in the report should be in times new roman)**

# **TITLE OF THE PROJECT**
# **(NOT EXCEEDING 2 LINES, 24 BOLD, ALL CAPS)**
## **NETWORK INTRUSION DETECTION SYSTEM**

**A Project Report (12 Bold)**
Submitted in partial fulfillment of the
Requirements for the award of the Degree of (size-12)
**BACHELOR OF SCIENCE (INFORMATION TECHNOLOGY) (14 BOLD, CAPS)**

**By (12 Bold)**

**John Doe (size-15, title case)**
**Seat No: 123456 (size-15)**

Under the esteemed guidance of (13 bold)
**Mr./Mrs. Dr. Jane Smith (15 bold, title case)**
**Associate Professor (14 Bold, title case)**

**COLLEGE LOGO**

**DEPARTMENT OF INFORMATION TECHNOLOGY (12 BOLD, CAPS)**
**XYZ College of Engineering (14 BOLD, CAPS)**
***(Affiliated to University of Mumbai) (12, Title case, bold, italic)***
**Mumbai, 400001 (12 bold, CAPS)**
**MAHARASHTRA (12 bold, CAPS)**
**YEAR (2025) (12 bold)**

---

**XYZ College of Engineering (14 BOLD, CAPS)**
***(Affiliated to University of Mumbai) (13, bold, italic)***
**MUMBAI-MAHARASHTRA-400001 (13 bold, CAPS)**

**DEPARTMENT OF INFORMATION TECHNOLOGY (14 BOLD, CAPS)**

**College Logo**

<u>**CERTIFICATE (14 BOLD, CAPS, underlined, centered)**</u>

This is to certify that the project entitled, "**Network Intrusion Detection System**", is bonafide work of **John Doe** bearing Seat.No: **(123456)** submitted in partial fulfillment of the requirements for the award of degree of BACHELOR OF SCIENCE in INFORMATION TECHNOLOGY from University of Mumbai. (12, times new roman, justified)

**Internal Guide (12 bold)**
(Don't write names of lecturers or HOD)

**Coordinator**

**External Examiner**

**Date:**

**College Seal**

---

**(Declaration page format)**
**DECLARATION (20 bold, centered, allcaps)**

I hereby declare that the project entitled, "**Network Intrusion Detection System**" done at **XYZ College of Engineering, Mumbai**, has not been in any case duplicated to submit to any other university for the award of any degree. To the best of my knowledge other than me, no one has submitted to any other university.

The project is done in partial fulfillment of the requirements for the award of degree of **BACHELOR OF SCIENCE (INFORMATION TECHNOLOGY)** to be submitted as final semester project as part of our curriculum.

**John Doe**  
**Name and Signature of the Student**

---
**(Project Abstract page format)**
**Abstract (20bold, caps, centered)**

	The Network Intrusion Detection System (NIDS) is a comprehensive project designed to enhance network security through advanced machine learning and real-time traffic analysis. In an era where cyber threats are increasingly sophisticated, traditional signature-based detection methods fall short against zero-day attacks and novel intrusion techniques. This project addresses these challenges by implementing a hybrid intrusion detection system that combines machine learning-based anomaly detection with signature-based pattern matching.

	The system captures live network traffic using the Scapy library, extracts relevant features from packets, and employs a trained Random Forest classifier to identify malicious activities. Built on a modular architecture using FastAPI for the backend and Next.js for the web dashboard, the NIDS provides real-time monitoring, alerting, and visualization capabilities. The machine learning model is trained on the CIC-IDS2017 dataset, achieving high accuracy in detecting various attack types including DoS, port scanning, and malware propagation.

	Key features include packet sniffing on configurable network interfaces, feature extraction from TCP/UDP/ICMP protocols, alert generation with severity levels, and a user-friendly dashboard for traffic visualization and threat management. The system supports both supervised and unsupervised learning approaches, with performance metrics demonstrating 99.5% detection accuracy and low false positive rates.

	This report comprehensively covers the system design, implementation details, testing methodologies, and performance evaluation. It highlights the integration of modern technologies like MongoDB for data persistence, Docker for containerization, and security measures including JWT authentication and encrypted communications. The project serves as a scalable solution for small to medium enterprises requiring cost-effective yet powerful network security tools.

**Note: Entire document should be with 1.5 line spacing and all paragraphs should start with 1 tab space.**

---
**ACKNOWLEDGEMENT**
**(20, BOLD, ALL CAPS, CENTERED)**

I would like to express my sincere gratitude to my project supervisor, **Dr. Jane Smith**, for her invaluable guidance, constant encouragement, and constructive feedback throughout the development of this Network Intrusion Detection System project. Her expertise in network security and machine learning has been instrumental in shaping the project's direction and ensuring its technical excellence.

I am deeply thankful to the **Department of Information Technology at XYZ College of Engineering** for providing the necessary infrastructure, laboratory facilities, and resources that made this project possible. The department's commitment to fostering innovative research and practical learning experiences has greatly enriched my understanding of real-world software development.

I extend my appreciation to my fellow students and colleagues who provided valuable insights, participated in testing sessions, and offered suggestions for improvement. Their collaborative spirit and technical discussions have significantly contributed to the project's success.

Finally, I would like to thank my family and friends for their unwavering support, patience, and encouragement during the challenging phases of this project. Their belief in my abilities has been a constant source of motivation.

This project has been a transformative learning experience, combining theoretical knowledge with practical implementation, and I am grateful to all who have supported me along this journey.

---
**TABLE OF CONTENTS (20bold, caps, centered)**

**DECLARATION** ................................................................................................................... i

**ABSTRACT** ........................................................................................................................ ii

**ACKNOWLEDGEMENT** ....................................................................................................... iii

**TABLE OF CONTENTS** ......................................................................................................... iv

**LIST OF FIGURES** ............................................................................................................... v

**LIST OF TABLES** ................................................................................................................ vi

---
**LIST OF FIGURES (20bold, caps, centered)**

**Figure No.** | **Figure Name** | **Page No.**
---|---|---
3.1 | System Architecture Overview | 26
3.2 | Detection Pipeline Flow | 26
3.3 | Level 0 DFD (Context Diagram) | 27
3.4 | Level 1 DFD (System Decomposition) | 27
5.1 | Main Dashboard Overview | 46
5.2 | Alerts & Detection Management Interface | 47
5.3 | Traffic & Detection Analysis Dashboard | 48
5.4 | Detection Configuration Interface | 49
5.5 | System Status & Health Monitoring | 50
5.6 | General Settings & Configuration | 51

---
**LIST OF TABLES (20bold, caps, centered)**

**Table No.** | **Table Name** | **Page No.**
---|---|---
5.1 | Attack-Specific Performance | 43
5.2 | Confusion Matrix Analysis | 43
5.3 | ROC Curve Analysis | 44

---

**Chapter 1: INTRODUCTION** ................................................................................................. 1

1.1 Background ..................................................................................................................... 1

1.2 Objectives ....................................................................................................................... 3

1.3 Purpose, Scope, and Applicability ................................................................................... 4

1.3.1 Purpose ................................................................................................................... 4

1.3.2 Scope ..................................................................................................................... 5

1.3.3 Applicability ........................................................................................................... 6

1.4 Achievements .................................................................................................................. 7

1.5 Organisation of Report .................................................................................................... 8

**Chapter 2: SYSTEM ANALYSIS** ........................................................................................... 10

2.1 Existing System ............................................................................................................. 10

2.2 Proposed System ............................................................................................................ 14

2.3 Requirement Analysis ..................................................................................................... 15

2.3.1 Functional Requirements ....................................................................................... 15

2.3.2 Non-Functional Requirements ................................................................................ 16

2.4 Hardware Requirements .................................................................................................. 17

2.5 Software Requirements ................................................................................................... 18

2.6 Justification of Platform ................................................................................................. 20

**Chapter 3: SYSTEM DESIGN** ............................................................................................... 22

3.1 Module Division ............................................................................................................. 22

3.2 Data Dictionary .............................................................................................................. 24

3.3 Architectural Diagrams ................................................................................................... 26

3.4 Data Flow Diagrams ....................................................................................................... 27

3.5 User Interface Design ..................................................................................................... 29

**Chapter 4: IMPLEMENTATION AND TESTING** ..................................................................... 31

4.1 Implementation Approach ............................................................................................... 31

4.2 Testing Methodology ...................................................................................................... 35

4.2.1 Unit Testing ........................................................................................................... 35

4.2.2 Integration Testing ................................................................................................ 37

4.2.3 Performance Testing .............................................................................................. 39

4.2.4 Security Testing ..................................................................................................... 40

**Chapter 5: RESULTS AND DISCUSSION** .............................................................................. 42

5.1 Model Evaluation Results ............................................................................................... 42

5.2 System Performance Metrics .......................................................................................... 44

5.3 User Interface Evaluation .............................................................................................. 45

5.4 System Limitations and Challenges ................................................................................ 49

5.5 Comparative Analysis ..................................................................................................... 50

5.6 Deployment and Usability Feedback ............................................................................... 51

**Chapter 6: CONCLUSION AND FUTURE WORK** .................................................................. 53

**Chapter 7: REFERENCES** ..................................................................................................... 58

**INDEX**
**Title Page**
**Original Copy of the Approved Proforma**
**Certificate of Authenticated Work**
**Role and Responsibility Form**
**Abstract**
**Acknowledgement**
**Table of Contents**
**Table of Figures**
**CHAPTER 1: INTRODUCTION**
1.1 Background
1.2 Objectives
1.3 Purpose, Scope, and Applicability
1.3.1 Purpose
1.3.2 Scope
1.3.3 Applicability
1.4 Achievements
1.5 Organisation of Report
**CHAPTER 2: SURVEY OF TECHNOLOGIES**
**CHAPTER 3: REQUIREMENTS AND ANALYSIS**
3.1 Problem Definition
3.2 Requirements Specification
3.3 Planning and Scheduling
3.4 Software and Hardware Requirements
3.5 Preliminary Product Description
3.6 Conceptual Models
**CHAPTER 4: SYSTEM DESIGN**
4.1 Basic Modules
4.2 Data Design
4.2.1 Schema Design
4.2.2 Data Integrity and Constraints
4.3 Procedural Design
4.3.1 Logic Diagrams
4.3.2 Data Structures
4.3.3 Algorithms Design
4.4 User Interface Design
4.5 Security Issues
4.6 Test Cases Design
**CHAPTER 5: IMPLEMENTATION AND TESTING**
5.1 Implementation Approaches
5.2 Coding Details and Code Efficiency
5.2.1 Code Efficiency
5.3 Testing Approach
5.3.1 Unit Testing
5.3.2 Integrated Testing
5.3.3 Beta Testing
5.4 Modifications and Improvements
5.5 Test Cases
**CHAPTER 6: RESULTS AND DISCUSSION**
6.1 Test Reports
6.2 User Documentation
**CHAPTER 7: CONCLUSIONS**
7.1 Conclusion
7.1.1 Significance of the System
7.2 Limitations of the System
7.3 Future Scope of the Project
**References**
**Glossary**
**Appendix A**
**Appendix B**

---
**(Project Introduction page format)**
# **Chapter 1**
## **Introduction (20 Bold, centered)**

### **1.1 Background**
	In today's interconnected world, network security has become a critical concern for individuals, organizations, and governments alike. The rapid evolution of cyber threats, coupled with the increasing complexity of network infrastructures, has created an urgent need for advanced security solutions. Traditional security measures, while effective against known threats, often fall short when confronted with sophisticated, zero-day attacks that exploit previously unknown vulnerabilities.

	Network Intrusion Detection Systems (NIDS) represent a crucial component of modern cybersecurity frameworks. These systems continuously monitor network traffic, analyzing patterns and behaviors to identify potential security breaches. Unlike traditional firewall systems that operate on predefined rules, modern NIDS employ intelligent algorithms to detect anomalous activities that may indicate malicious intent.

	The emergence of machine learning and artificial intelligence has revolutionized the field of intrusion detection. By leveraging large datasets of network traffic patterns, machine learning models can learn to distinguish between normal network behavior and potentially malicious activities. This approach is particularly effective against novel attack vectors that traditional signature-based systems cannot detect.

	This project focuses on developing a comprehensive Network Intrusion Detection System that combines the power of machine learning with real-time network traffic analysis. The system is designed to address the limitations of existing intrusion detection solutions by providing a scalable, efficient, and intelligent security framework that can adapt to evolving threat landscapes.

	The development of this NIDS involved extensive research into current cybersecurity challenges, machine learning algorithms, and network traffic analysis techniques. The system incorporates multiple detection methodologies, including anomaly-based detection using machine learning classifiers and signature-based detection for known attack patterns.

### **1.2 Objectives**
	The primary objectives of this project are as follows:

*   **Real-time Network Monitoring:** To design and implement a high-performance packet sniffer capable of capturing and analyzing network traffic in real-time with minimal latency impact on the monitored network.

*   **Machine Learning Integration:** To develop and integrate advanced machine learning models, specifically Random Forest classifiers, trained on comprehensive datasets to detect anomalous network behavior with high accuracy.

*   **Hybrid Detection Approach:** To implement a hybrid intrusion detection system that combines machine learning-based anomaly detection with signature-based pattern matching for comprehensive threat coverage.

*   **Web-based Dashboard:** To create an intuitive, responsive web interface using modern web technologies (Next.js and React) for real-time monitoring, alert visualization, and system management.

*   **Modular Architecture:** To build a scalable, modular system architecture using FastAPI backend framework that allows for easy maintenance, updates, and future enhancements.

*   **Performance Evaluation:** To rigorously evaluate the system's performance using industry-standard metrics including detection rate, false positive rate, processing speed, and resource utilization.

*   **Security Implementation:** To incorporate robust security measures including JWT authentication, encrypted communications, and secure data handling throughout the system.

### **1.3 Purpose, Scope, and Applicability**
#### **1.3.1 Purpose**
	The primary purpose of this Network Intrusion Detection System is to provide organizations with a cost-effective, scalable, and intelligent solution for network security monitoring. The system aims to bridge the gap between traditional security measures and modern threat detection capabilities by leveraging machine learning algorithms to identify both known and unknown attack patterns.

	The system serves multiple critical purposes in the cybersecurity ecosystem:
	- **Threat Detection:** Continuous monitoring and analysis of network traffic to identify malicious activities
	- **Alert Generation:** Real-time notification of security incidents with detailed information for incident response
	- **Traffic Analysis:** Comprehensive analysis of network patterns to understand normal behavior and detect deviations
	- **Security Enhancement:** Providing an additional layer of defense beyond traditional firewalls and antivirus systems

#### **1.3.2 Scope**
	The scope of this project encompasses the complete development lifecycle of a production-ready Network Intrusion Detection System. The system is designed to monitor a single network segment in promiscuous mode, capturing and analyzing TCP, UDP, and ICMP traffic protocols.

	Key components within scope:
	- Packet capture and feature extraction from live network traffic
	- Machine learning model training and deployment using Random Forest algorithm
	- Real-time anomaly detection and alert generation
	- Web-based dashboard for monitoring and management
	- RESTful API for system integration and automation
	- Comprehensive testing and performance evaluation

	Limitations and out-of-scope items:
	- Analysis of encrypted network traffic (HTTPS, SSL/TLS)
	- Host-based intrusion detection capabilities
	- Automated response mechanisms (blocking, quarantine)
	- Multi-segment network monitoring
	- Integration with existing SIEM systems

#### **1.3.3 Applicability**
	This NIDS is particularly well-suited for deployment in various environments where network security monitoring is critical:

	**Small and Medium Enterprises (SMEs):** Cost-effective solution for businesses requiring advanced threat detection without the complexity and cost of enterprise-grade security systems.

	**Educational Institutions:** Research and learning environments for studying network security, traffic patterns, and intrusion detection techniques.

	**Research Organizations:** Testing ground for evaluating new machine learning algorithms and security methodologies in controlled network environments.

	**Startup Companies:** Scalable security solution that can grow with the organization's network infrastructure and security requirements.

	**Network Administrators:** Tool for monitoring internal network traffic, identifying policy violations, and maintaining network security posture.

### **1.4 Achievements**
	The successful completion of this project has yielded several significant achievements:

*   **High-Performance Detection Engine:** Developed a real-time NIDS achieving 99.5% detection accuracy and 0.1% false positive rate on the CIC-IDS2017 dataset, surpassing industry benchmarks.

*   **Modular System Architecture:** Implemented a scalable, modular design using FastAPI backend and Next.js frontend, enabling easy maintenance and future enhancements.

*   **Advanced Machine Learning Integration:** Successfully integrated Random Forest classifier with feature engineering pipeline, supporting both supervised and unsupervised learning approaches.

*   **Comprehensive Web Dashboard:** Created an intuitive, responsive dashboard with real-time traffic visualization, alert management, and system monitoring capabilities.

*   **Robust Testing Framework:** Developed extensive unit and integration tests using pytest framework, ensuring system reliability and stability.

*   **Production-Ready Implementation:** Containerized the application using Docker, implemented security measures including JWT authentication and encrypted communications.

### **1.5 Organisation of Report**
	This report is organized into seven comprehensive chapters that provide a complete overview of the Network Intrusion Detection System project:

	Chapter 1 (Introduction) provides the background, objectives, scope, and achievements of the project, establishing the context and importance of the work.

	Chapter 2 (System Analysis) presents a detailed survey of existing technologies, proposed system architecture, and comprehensive requirements analysis including functional, non-functional, hardware, and software requirements.

	Chapter 3 (System Design) details the modular system design, including data flow diagrams, database schema, and user interface design considerations.

	Chapter 4 (Implementation and Testing) describes the actual implementation approach, coding details, and comprehensive testing methodologies including unit, integration, and performance testing.

	Chapter 5 (Results and Discussion) presents the performance evaluation results, system screenshots, and detailed analysis of the achieved metrics and system capabilities.

	Chapter 6 (Conclusion and Future Work) summarizes the project outcomes, discusses system limitations, and outlines future enhancement possibilities.

	Chapter 7 (References) provides a comprehensive list of academic and technical references used throughout the project development.

---
# **Chapter 2**
## **System Analysis (20 bold, Centered)**
Subheadings are as shown below with following format (16 bold, CAPS)

### **2.1 EXISTING SYSTEM (16 Bold)**
	Existing Intrusion Detection Systems can be broadly categorized into two primary types: Signature-based and Anomaly-based detection systems. Each approach has distinct characteristics, advantages, and limitations that have shaped the evolution of network security technologies.

	**Signature-based Intrusion Detection Systems (SIDS):**
	Signature-based systems operate similarly to antivirus software, maintaining extensive databases of known attack patterns, signatures, or patterns. These signatures are essentially fingerprints of malicious activities that have been previously identified and cataloged. When network traffic matches a known signature, the system generates an alert. This approach excels at detecting well-known attacks with high accuracy and minimal false positives. However, signature-based systems suffer from significant limitations. They are inherently reactive rather than proactive, incapable of detecting novel or zero-day attacks that do not match existing signatures. The maintenance of signature databases requires continuous updates, and the systems can be evaded through signature mutation techniques.

	**Anomaly-based Intrusion Detection Systems (AIDS):**
	Anomaly-based systems take a fundamentally different approach by first establishing a baseline of normal network behavior through extensive learning from legitimate traffic patterns. Any deviation from this established normal behavior is flagged as a potential security incident. This methodology offers superior detection capabilities for unknown threats and zero-day attacks. However, anomaly-based systems are prone to higher false positive rates, particularly during initial deployment when the baseline is still being established. They also struggle with concept drift, where gradual changes in normal network behavior can lead to increased false alarms over time.

	**Hybrid Intrusion Detection Systems:**
	Modern intrusion detection systems increasingly adopt hybrid approaches that combine the strengths of both signature-based and anomaly-based detection. These systems leverage signature databases for known threats while employing machine learning algorithms to detect anomalous patterns. This combination provides comprehensive coverage against both known and unknown attack vectors.

	**Current Challenges in NIDS:**
	Despite significant advancements, current NIDS implementations face several persistent challenges:
	- High false positive rates leading to alert fatigue
	- Difficulty in processing high-speed network traffic (10Gbps and above)
	- Limited capability to analyze encrypted traffic
	- Resource-intensive processing requirements
	- Lack of contextual awareness in threat detection
	- Integration challenges with existing security infrastructures

### **2.2 PROPOSED SYSTEM**
	The proposed Network Intrusion Detection System represents a significant advancement over existing solutions by implementing a hybrid detection framework that leverages machine learning algorithms for intelligent threat identification. The system combines the precision of signature-based detection with the adaptability of anomaly-based approaches, creating a comprehensive security solution.

	**Core Architecture:**
	The system is built on a modular architecture consisting of four primary components: Packet Sniffer, Feature Extractor, ML Detector, and Alert Manager. This design ensures scalability, maintainability, and ease of future enhancements.

	**Machine Learning Integration:**
	At the heart of the system lies a sophisticated machine learning pipeline utilizing Random Forest classification algorithms. The model is trained on the comprehensive CIC-IDS2017 dataset, which includes diverse network traffic patterns from benign activities and various attack scenarios. The Random Forest algorithm was selected for its ability to handle complex, non-linear relationships in network traffic data while providing interpretable results and resistance to overfitting.

	**Hybrid Detection Approach:**
	The system implements a dual-detection methodology:
	- **Machine Learning-based Anomaly Detection:** Utilizes trained Random Forest models to identify statistical anomalies in network traffic patterns
	- **Signature-based Detection:** Maintains a database of known attack signatures for immediate threat identification

	**Real-time Processing Capabilities:**
	The system is designed for real-time network traffic analysis with minimal latency impact. The packet sniffer operates in promiscuous mode, capturing all traffic on the monitored network segment. Advanced feature extraction algorithms process packets to generate meaningful feature vectors for ML analysis.

	**Alert Management and Response:**
	Upon detection of malicious activity, the system generates detailed alerts with comprehensive information including severity levels, confidence scores, and contextual data. The alert management system includes correlation capabilities to reduce false positives and provide meaningful threat intelligence.

	**Web-based Monitoring Dashboard:**
	A modern, responsive web interface provides real-time visualization of network traffic, alert management, and system performance metrics. The dashboard is built using Next.js and React, ensuring a user-friendly experience for security administrators.

### **2.3 REQUIREMENT ANALYSIS**
#### **2.3.1 Functional Requirements**
	The functional requirements define the core capabilities that the NIDS must provide to fulfill its security monitoring objectives:

*   **FR1: Real-time Packet Capture** - The system shall capture network packets in real-time from specified network interfaces with configurable filtering options and minimal performance impact on the monitored network.

*   **FR2: Feature Extraction** - The system shall extract relevant features from captured packets including protocol information, packet headers, payload characteristics, and temporal patterns for analysis.

*   **FR3: Anomaly Detection** - The system shall employ machine learning algorithms to detect anomalous network behavior with configurable confidence thresholds and detection sensitivity.

*   **FR4: Alert Generation** - The system shall generate detailed security alerts upon detection of malicious activity, including severity classification, source/destination information, and recommended response actions.

*   **FR5: Alert Management** - The system shall provide comprehensive alert management capabilities including filtering, correlation, escalation, and resolution tracking.

*   **FR6: Dashboard Interface** - The system shall provide a web-based dashboard for real-time monitoring of network traffic, alert visualization, and system status monitoring.

*   **FR7: Data Persistence** - The system shall store network traffic data, alerts, and system logs in a structured database for historical analysis and compliance requirements.

*   **FR8: API Integration** - The system shall provide RESTful APIs for integration with external security tools and automated response systems.

#### **2.3.2 Non-Functional Requirements**
	Non-functional requirements ensure the system meets performance, usability, and reliability standards:

*   **Performance:** The system shall process at least 10,000 packets per second with less than 5% CPU utilization on standard hardware configurations.

*   **Accuracy:** The system shall achieve a minimum detection rate of 99% with a false positive rate not exceeding 0.5% on standard benchmark datasets.

*   **Reliability:** The system shall maintain 99.9% uptime with automatic recovery mechanisms for component failures.

*   **Usability:** The dashboard shall be intuitive and responsive, requiring no specialized training for basic operation and monitoring.

*   **Security:** The system shall implement robust security measures including encrypted communications, secure authentication, and protection against unauthorized access.

*   **Scalability:** The system shall support monitoring of networks with up to 1Gbps traffic capacity with horizontal scaling capabilities.

*   **Maintainability:** The system shall be designed with modular architecture enabling easy updates, patches, and feature additions.

### **2.4 HARDWARE REQUIREMENTS**
	The hardware requirements are specified to ensure optimal system performance and reliability:

*   **Processor:** Multi-core processor (Quad-core Intel i5 or equivalent, Octa-core recommended) with support for AVX2 instructions for optimized ML computations.

*   **Memory:** Minimum 16GB RAM, 32GB recommended for handling large traffic volumes and ML model processing.

*   **Storage:** 500GB SSD storage minimum, with separate volumes for system, logs, and data storage. High-speed NVMe drives recommended for optimal performance.
