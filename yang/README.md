# i2nsf-yang

The [IETF (Internet Engineering Taskforce)](https://www.ietf.org/) 
[I2NSF (Interface to Network Security Functions) workgroup](https://datatracker.ietf.org/wg/i2nsf/charter/)
working group aims to define software interface specifciations for functions that
ensure network integrity, confidentiality and availability so that one implementors
can translate well defined user requirements into enforcable policies.

The YANG data models in this repository are related to the following documents:

* I2NSF Capability YANG Data Model
 [draft-ietf-i2nsf-capability-data-model-32](https://datatracker.ietf.org/doc/draft-ietf-i2nsf-capability-data-model/)
 
  - This document gives the motivation for controlling access policies in a data center setup from a single managment point
  This can make it efficient to manage multiple devices which may be changed. An XML type schema is described for 
  controlling network traffic according to protocol, port, orginating IP address etc.
 
* Consumer-Facing Interface YANG Data Model
 [draft-ietf-i2nsf-consumer-facing-interface-dm-27](https://datatracker.ietf.org/doc/draft-ietf-i2nsf-consumer-facing-interface-dm/)
 
  - This document specifies what policies should be available in a friendly interface for the operator. It uses an XML
  schema that can be used to create a web interface. Firewalls, DDoS prevention and time based access to internet
  resources are considered.

* NSF-Facing Interface YANG Data Model
 [draft-ietf-i2nsf-nsf-facing-interface-dm-29](https://datatracker.ietf.org/doc/draft-ietf-i2nsf-nsf-facing-interface-dm/)
 
  - This document allows vendors to specify how policies should be enforced on their hardware so that one obtains a consistent
  behaviour. It allows for different types of actions based on both applied system policies and in response to external events 
  such as attacks. 

* Registration Interface YANG Data Model
 [draft-ietf-i2nsf-registration-interface-dm-23](https://datatracker.ietf.org/doc/draft-ietf-i2nsf-registration-interface-dm/)

  - This document allows for querying of the NSF capabilities from a single interface.

* Monitoring Interface YANG Data Model
 [draft-ietf-i2nsf-nsf-monitoring-data-model-20](https://datatracker.ietf.org/doc/draft-ietf-i2nsf-nsf-monitoring-data-model/)
 
   - This document proposes an information model and the corresponding YANG data model for monitoring Network Security Functions 
   (NSFs) in the Interface to Network Security Functions (I2NSF) framework.
