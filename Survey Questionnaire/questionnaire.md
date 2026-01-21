## Questionnaire Overview

This questionnaire aims to gain an in-depth understanding of the current applications, effectiveness, and challenges of **multi-source knowledge fusion** in **Advanced Persistent Threat (APT) attack analysis**, and to provide data support and directional guidance for related research and practical implementations. Against the backdrop of increasingly complex and stealthy APT attacks, relying on a single knowledge source is often insufficient to support efficient and accurate detection and response. Consequently, multi-source knowledge fusion has become a critical enabling approach for APT analysis. It refers to the integration and correlation of knowledge from multiple dimensions to enhance the capabilities of APT attack detection, response, and provenance-based investigation.
This questionnaire focuses on the following three core categories of knowledge sources:

### Benign Behavior Knowledge
Knowledge that characterizes normal network and system behaviors, typically obtained through data analysis and model mining, and used to distinguish normal activities from anomalous behaviors.

### Threat Intelligence Knowledge
Information related to attackers, attack tools, and attack resources, sourced from intelligence centers, vulnerability databases, and security research, and used to identify and defend against known threats.

### Attack Representation Knowledge
Knowledge that describes attack characteristics and behavioral patterns, derived from expert experience and public knowledge bases (e.g., ATT&CK), and used to identify attack tactics, techniques, and procedures (TTPs).

## Acknowledgment

Through your valuable experience and insights, we aim to better evaluate the effectiveness of multi-source knowledge fusion in APT attack analysis and explore directions for further improvement. Your responses will be of great significance to both research and practice in the cybersecurity domain.  
Thank you for your participation and support.

## Part I: Basic Information of the Respondent

**1. What is your current role in the field of cybersecurity?**  *Single choice question*

- A. Security Operations Engineer  
- B. Security Analyst  
- C. Threat Intelligence Expert  
- D. Security Architect  
- E. Security Researcher  
- F. Security Product Developer  
- G. Other (please specify)

**2. Which industry does your organization belong to?**  *Single choice question*

- A. Government / Defense  
- B. Finance / Banking  
- C. Energy / Utilities  
- D. Technology / Internet  
- E. Healthcare  
- F. Education / Research  
- G. Other (please specify)

**3. How many years of experience do you have in security operations–related work?**  
*Single choice question*

- A. Less than 1 year  
- B. 1–3 years  
- C. 3–5 years  
- D. More than 5 years

**4. What is the size of your organization?**  
*Single choice question*

- A. Small-sized enterprise (1–50 employees)  
- B. Medium-sized enterprise (51–500 employees)  
- C. Large-sized enterprise (501–5,000 employees)  
- D. Very large enterprise (more than 5,000 employees)

## Part II: Assessment of Multi-Source Knowledge Usage

**1. In your current APT analysis work, how frequently do you use the following knowledge sources?**  
*Matrix question*

| Knowledge Source | Never Used | Occasionally Used | Frequently Used | Always Used |
|------------------|------------|-------------------|-----------------|-------------|
| Attack Representation Knowledge (e.g., ATT&CK framework, attack pattern databases, TTPs) | ○ | ○ | ○ | ○ |
| Threat Intelligence Knowledge (e.g., IOCs, threat reports) | ○ | ○ | ○ | ○ |
| Benign Behavior Knowledge (e.g., normal network/system behavior baselines) | ○ | ○ | ○ | ○ |

**2. To what extent do you think the following knowledge sources contribute to improving the accuracy of APT attack detection?**  
*Matrix question*

| Knowledge Source | No Contribution | Minor Contribution | Moderate Contribution | Significant Contribution |
|------------------|-----------------|--------------------|-----------------------|--------------------------|
| Attack Representation Knowledge | ○ | ○ | ○ | ○ |
| Threat Intelligence Knowledge | ○ | ○ | ○ | ○ |
| Benign Behavior Knowledge | ○ | ○ | ○ | ○ |

**3. How does your organization integrate different types of knowledge sources for APT analysis?**  
*Multiple choice question*

- A. Manual correlation and analysis  
- B. Integration through a Security Information and Event Management (SIEM) system  
- C. Integration through a Threat Intelligence Platform (TIP)  
- D. Using custom scripts or tools  
- E. Little to no integration; different knowledge sources are used independently  
- F. Other (please specify)

**4. How easy or difficult is it for you to access the following knowledge sources in your work?**
*Matrix question*
| Knowledge Source             | Very Difficult | Relatively Difficult | Neutral | Relatively Easy | Very Easy |
|------------------------------|----------------|--------------------|---------|----------------|-----------|
| Attack Representation Knowledge | ○ | ○ | ○ | ○ | ○ |
| Threat Intelligence Knowledge   | ○ | ○ | ○ | ○ | ○ |
| Benign Behavior Knowledge       | ○ | ○ | ○ | ○ | ○ |

## Part III: Assessment of Multi-Source Knowledge Usage
**1. In which stages of APT attack analysis do you believe multi-source knowledge fusion is most effective?**  
*Matrix question*
|                              | Slightly Effective  | Moderately Effective | Very Effective | Extremely Effective |
|------------------------------|----------------|--------------------|---------|----------------|
| Data Reduction    | ○ | ○ | ○ | ○ |
| Early Detection   | ○ | ○ | ○ | ○ |
| Intent Inference  | ○ | ○ | ○ | ○ |
| Impact Assessment | ○ | ○ | ○ | ○ |
| Response Planning | ○ | ○ | ○ | ○ |
| Attack Attribution| ○ | ○ | ○ | ○ |

**2. Based on your experience, to what extent does multi-source knowledge fusion alter APT analysis metrics compared to single-source knowledge?**  
*Matrix question*
|                              | Slightly Effective  | Moderately Effective | Very Effective | Extremely Effective |
|------------------------------|----------------|--------------------|---------|----------------|
| False Positive    | ○ | ○ | ○ | ○ |
| False Negative   | ○ | ○ | ○ | ○ |
| MTTD  | ○ | ○ | ○ | ○ |
| MTTR | ○ | ○ | ○ | ○ |

**3. Which knowledge fusion methods for APT analysis have you encountered?**
*Single choice question*
- A. Rule-based knowledge fusion (e.g., predefined association rules)
- B. Graph-based knowledge fusion (e.g., knowledge graph techniques)
- C. Machine learning / deep learning-based knowledge fusion
- D. Large language model-based knowledge fusion
- E. Others (please specify)

  
**4. Which of the following knowledge fusion methods do you think is most effective for APT analysis?**
*Single choice question*
- A. Rule-based knowledge fusion (e.g., predefined association rules)
- B. Graph-based knowledge fusion (e.g., knowledge graph techniques)
- C. Machine learning / deep learning-based knowledge fusion
- D. Large language model-based knowledge fusion
- E. Others (please specify)

**5. In APT attack analysis, which combination of knowledge sources do you consider most effective? Please rank the following knowledge source combinations from most effective to least effective (1 = most effective, 4 = least effective)** 
*Ranking question*
Attack representation knowledge + Threat intelligence knowledge
Attack representation knowledge + Benign behavior knowledge
Threat intelligence knowledge + Benign behavior knowledge
Attack representation knowledge + Threat intelligence knowledge + Benign behavior knowledge

## Part IV: Challenges and Improvement Recommendations
**1. What are the primary challenges you encounter when integrating multi-source knowledge for APT analysis?** 
*Matrix question*
|                              | No Challenge  | Minor Challenge | Moderate Challenge | Major Challenge |
|------------------------------|----------------|--------------------|---------|----------------|
| Iconsistent or Conflicting Knowledge Sources    | ○ | ○ | ○ | ○ |
| Untimely Knowledge Updates   | ○ | ○ | ○ | ○ |
| Non-uniform Knowledge Representation  | ○ | ○ | ○ | ○ |
| Lack of Effective Fusion Methods | ○ | ○ | ○ | ○ |

**2. Which technologies do you think can improve the effectiveness of multi-source knowledge in APT analysis?** 
*Multiple choice question*
- A. Knowledge graph technologies
- B. Graph neural networks
- C. Large language models
- D. Automated knowledge extraction and update techniques
- E. Standardized knowledge representation frameworks
- F. Others (please specify)

**3. What are your suggestions for enhancing the effectiveness of multi-source intelligence in APT attack analysis?** 
*Fill-in-the-blank question*
