# Judge Question Bank for Project Sentinel

This document contains a curated list of challenging questions that judges at a national-level competition are likely to ask. They are categorized to help you structure your preparation.

---

### **Category 1: Technical Deep Dive & Architecture**

These questions test your understanding of the core technology and the trade-offs you've made.

1.  **AI / Machine Learning:**
    *   "You're using Random Forest and Isolation Forest. Why did you choose these specific models over more modern deep learning approaches like LSTMs or Transformers, which are often used for sequential data like network traffic?"
    *   "What is your methodology for labeling the training data for your supervised models? How do you ensure the quality of these labels and minimize bias?"
    *   "How do you plan to handle 'model drift'? As your clients' 'normal' network behavior evolves, how will you retrain and redeploy models without causing service interruptions or a drop in accuracy?"
    *   "What are the computational requirements for real-time model inference? Can your system handle a saturated 1 Gbps link on your proposed hardware, and what is your plan to scale to 10 Gbps and beyond?"

2.  **Blockchain Integration:**
    *   "Your blockchain integrity check is a key innovation. However, if an attacker gains root access to the NIDS appliance itself, couldn't they just compromise the node's connection to the blockchain, effectively bypassing the integrity check?"
    *   "What is the actual performance overhead of the blockchain component? Can you quantify the latency in milliseconds for both the startup integrity check and the real-time logging of a critical alert?"
    *   "If you are using a private blockchain, what consensus mechanism is in place, and how do you protect against a 51% attack if an attacker manages to compromise a majority of your distributed NIDS nodes?"

3.  **System Performance & Scalability:**
    *   "At what specific throughput and packets-per-second rate does your current prototype begin to experience packet loss? What is the primary bottleneck—CPU, memory bandwidth, or I/O?"
    *   "How does your system's architecture handle IPv6 traffic and its unique security challenges, such as those related to extension headers? Are your detection models explicitly trained on IPv6-specific attack vectors?"
    *   "You're using MongoDB as your backend. In a large-scale DDoS attack scenario that could generate thousands of alerts per second, how do you prevent the database itself from becoming a bottleneck and failing?"

---

### **Category 2: Business, Go-To-Market & Financials**

These questions probe the commercial viability of your project.

1.  **Business Model & Pricing:**
    *   "What is your proposed pricing strategy? Will you charge per appliance, via a subscription based on network throughput, or per number of monitored endpoints? How did you validate this model?"
    *   "The hardware appliance model has significant costs and logistical complexities (inventory, shipping, support) compared to a pure software-as-a-service (SaaS) model. Why are you certain this is the right initial approach for the Indian market?"
    *   "What specific, measurable milestones will you achieve with the seed funding you're asking for? What key performance indicators (KPIs) will you present to investors to justify a larger Series A round?"

2.  **Customer Acquisition & Sales:**
    *   "Who is your 'beachhead' customer? Can you describe the specific profile of the first 10 customers you will target to gain initial traction and build case studies?"
    *   "Do you or your advisors have prior experience in navigating the complex government procurement process? What is your strategy for getting your first paid pilot with a government entity?"
    *   "What does your customer support model look like? When a hospital's security appliance raises a critical alert at 3 AM on a Sunday, what is the process that follows?"

---

### **Category 3: Competitive Landscape & Defensibility**

These questions test your awareness of the market and your project's unique position.

1.  **Competition:**
    *   "Powerful open-source tools like Suricata and Zeek are free and highly effective when managed by a skilled engineer. Why would a cost-sensitive organization pay for your solution instead of deploying an open-source alternative?"
    *   "How do you plan to compete with the major cloud providers—AWS, Azure, and GCP—who offer their own native network threat detection services that are deeply integrated into their cloud ecosystems?"
    *   "What is your 'unfair advantage'? What is the long-term 'moat' around your business that will prevent a large, well-funded competitor from simply replicating your features in 12-18 months?"

2.  **Market Positioning:**
    *   "Your solution seems enterprise-grade. Is there a risk that you are 'too complex' or 'too expensive' for the large but underserved Small-to-Medium Business (SMB) market in India?"
    *   "The data you collect from your pilot customers is invaluable for training your models. How does your data privacy policy address this? How will you convince your first customers to share their highly sensitive network metadata with a startup?"

---

### **Category 4: Vision & Strategic Thinking**

These questions explore your long-term vision and ability to think strategically.

1.  **Product Evolution:**
    *   "Your plan to move from IDS (detection) to IPS (prevention) is a critical step. A single false positive in an IPS can take down a business-critical application. What is your strategy to ensure near-perfect reliability and give customers the confidence to enable automated blocking?"
    *   "Looking 5 years into the future, what do you believe will be the single biggest change in the cyber threat landscape, and how is your platform's core architecture designed today to adapt to that future change?"
    *   "You mentioned a decentralized threat intelligence network as a future goal. This is a classic 'chicken-and-egg' problem. How would you incentivize the very first customers to share their data when the network has few participants?"

2.  **Team & Execution:**
    *   "What is the single most important area of expertise currently missing from your founding team, and who would be your first key hire with the funding you receive?"
    *   "Can you describe a time during this project when there was a major technical disagreement within the team? How was it resolved?"
    *   "Beyond the technology, why are *you* the right team to dedicate the next 10 years of your lives to solving this massive problem? What drives your passion for this specific mission?"