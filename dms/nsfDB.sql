-- MySQL dump 10.13  Distrib 8.0.33, for Linux (x86_64)
--
-- Host: localhost    Database: nsf
-- ------------------------------------------------------
-- Server version	8.0.33-0ubuntu0.20.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `action-capabilities`
--

DROP TABLE IF EXISTS `action-capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `action-capabilities` (
  `id` int NOT NULL,
  `ingress-action-capability` set('pass','drop','reject','mirror','rate-limit') DEFAULT NULL,
  `egress-action-capability` set('pass','drop','reject','mirror','rate-limit','invoke-signaling','tunnel-encapsulation','forwarding','transformation','http-to-coap','nat') DEFAULT NULL,
  `log-action-capability` set('rule-log','session-log') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `action-capabilities`
--

LOCK TABLES `action-capabilities` WRITE;
/*!40000 ALTER TABLE `action-capabilities` DISABLE KEYS */;
INSERT INTO `action-capabilities` VALUES (1,'pass,drop','pass,drop',NULL);
/*!40000 ALTER TABLE `action-capabilities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `advanced-nsf-capabilities`
--

DROP TABLE IF EXISTS `advanced-nsf-capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `advanced-nsf-capabilities` (
  `id` int NOT NULL,
  `anti-ddos-capability` set('packet-rate','flow-rate','byte-rate') DEFAULT NULL,
  `ips-capability` set('signature-set','exception-signature') DEFAULT NULL,
  `anti-virus-capability` set('detect','exception-file') DEFAULT NULL,
  `url-filtering-capability` set('pre-defined','user-defined') DEFAULT NULL,
  `voip-vocn-filtering-capability` set('call-id','user-agent') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `advanced-nsf-capabilities`
--

LOCK TABLES `advanced-nsf-capabilities` WRITE;
/*!40000 ALTER TABLE `advanced-nsf-capabilities` DISABLE KEYS */;
INSERT INTO `advanced-nsf-capabilities` VALUES (0,NULL,NULL,NULL,NULL,NULL),(1,NULL,NULL,NULL,'pre-defined,user-defined',NULL),(2,'packet-rate,flow-rate,byte-rate',NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `advanced-nsf-capabilities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `bandwidth`
--

DROP TABLE IF EXISTS `bandwidth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `bandwidth` (
  `id` int NOT NULL,
  `outbound` bigint unsigned DEFAULT NULL,
  `inbound` bigint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `bandwidth`
--

LOCK TABLES `bandwidth` WRITE;
/*!40000 ALTER TABLE `bandwidth` DISABLE KEYS */;
INSERT INTO `bandwidth` VALUES (1,1000000000,1000000000);
/*!40000 ALTER TABLE `bandwidth` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `condition-capabilities`
--

DROP TABLE IF EXISTS `condition-capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `condition-capabilities` (
  `id` int NOT NULL,
  `generic-nsf-capabilities` int DEFAULT NULL,
  `advanced-nsf-capabilities` int DEFAULT NULL,
  `context-capabilities` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `generic-nsf-capabilities` (`generic-nsf-capabilities`),
  KEY `advanced-nsf-capabilities` (`advanced-nsf-capabilities`),
  KEY `context-capabilities` (`context-capabilities`),
  CONSTRAINT `condition-capabilities_ibfk_1` FOREIGN KEY (`generic-nsf-capabilities`) REFERENCES `generic-nsf-capabilities` (`id`),
  CONSTRAINT `condition-capabilities_ibfk_2` FOREIGN KEY (`advanced-nsf-capabilities`) REFERENCES `advanced-nsf-capabilities` (`id`),
  CONSTRAINT `condition-capabilities_ibfk_3` FOREIGN KEY (`context-capabilities`) REFERENCES `context-capabilities` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `condition-capabilities`
--

LOCK TABLES `condition-capabilities` WRITE;
/*!40000 ALTER TABLE `condition-capabilities` DISABLE KEYS */;
INSERT INTO `condition-capabilities` VALUES (1,1,0,0),(2,1,0,1),(3,0,1,0),(4,0,2,0);
/*!40000 ALTER TABLE `condition-capabilities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `context-capabilities`
--

DROP TABLE IF EXISTS `context-capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `context-capabilities` (
  `id` int NOT NULL,
  `time-capabilities` set('absolute-time','periodic-time') DEFAULT NULL,
  `application-filter-capabilities` set('http','https','http2','https2','ftp','ssh','telnet','smtp','pop3','pop3s','imap','imaps') DEFAULT NULL,
  `device-type-capabilities` set('computer','mobile-phone','voip-vocn-phone','tablet','network-infrastructure-device','iot','ot','vehicle') DEFAULT NULL,
  `user-condition-capabilities` set('user','group') DEFAULT NULL,
  `geographic-capabilities` set('source-location','destination-location') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `context-capabilities`
--

LOCK TABLES `context-capabilities` WRITE;
/*!40000 ALTER TABLE `context-capabilities` DISABLE KEYS */;
INSERT INTO `context-capabilities` VALUES (0,NULL,NULL,NULL,NULL,NULL),(1,'absolute-time,periodic-time',NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `context-capabilities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cpu`
--

DROP TABLE IF EXISTS `cpu`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cpu` (
  `id` int NOT NULL,
  `model` varchar(255) DEFAULT NULL,
  `clock-speeed` smallint unsigned DEFAULT NULL,
  `cores` tinyint unsigned DEFAULT NULL,
  `threads` smallint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cpu`
--

LOCK TABLES `cpu` WRITE;
/*!40000 ALTER TABLE `cpu` DISABLE KEYS */;
INSERT INTO `cpu` VALUES (1,'Intel(R) Core(TM) i7-10510U',1800,4,8);
/*!40000 ALTER TABLE `cpu` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `disk`
--

DROP TABLE IF EXISTS `disk`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `disk` (
  `id` int NOT NULL,
  `capacity` int unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `disk`
--

LOCK TABLES `disk` WRITE;
/*!40000 ALTER TABLE `disk` DISABLE KEYS */;
INSERT INTO `disk` VALUES (1,239000);
/*!40000 ALTER TABLE `disk` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `event-capabilities`
--

DROP TABLE IF EXISTS `event-capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `event-capabilities` (
  `id` int NOT NULL,
  `system-event-capability` set('access-violation','configuration-change') DEFAULT NULL,
  `system-alarm-capability` set('memory-alarm','cpu-alarm','disk-alarm','hardware-alarm','interface-alarm') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `event-capabilities`
--

LOCK TABLES `event-capabilities` WRITE;
/*!40000 ALTER TABLE `event-capabilities` DISABLE KEYS */;
INSERT INTO `event-capabilities` VALUES (0,NULL,NULL),(1,'access-violation,configuration-change','memory-alarm,cpu-alarm');
/*!40000 ALTER TABLE `event-capabilities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `generic-nsf-capabilities`
--

DROP TABLE IF EXISTS `generic-nsf-capabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `generic-nsf-capabilities` (
  `id` int NOT NULL,
  `ethernet-capability` set('source-mac-address','destination-mac-address','ether-type') DEFAULT NULL,
  `ipv4-capability` set('dscp','ecn','total-length','ttl','next-header','source-address','destination-address','flow-direction','ihl','identification','fragment-offset') DEFAULT NULL,
  `ipv6-capability` set('dscp','ecn','total-length','ttl','next-header','source-address','destination-address','flow-direction','flow-label') DEFAULT NULL,
  `icmpv4-capability` set('type','code') DEFAULT NULL,
  `icmpv6-capability` set('type','code') DEFAULT NULL,
  `tcp-capability` set('source-port-number','destination-port-number','flags','options','data-offset','reserved','window-size','urgent-pointer') DEFAULT NULL,
  `udp-capability` set('source-port-number','destination-port-number','length') DEFAULT NULL,
  `sctp-capability` set('source-port-number','destination-port-number','length','chunk-type') DEFAULT NULL,
  `dccp-capability` set('source-port-number','destination-port-number','service-code') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `generic-nsf-capabilities`
--

LOCK TABLES `generic-nsf-capabilities` WRITE;
/*!40000 ALTER TABLE `generic-nsf-capabilities` DISABLE KEYS */;
INSERT INTO `generic-nsf-capabilities` VALUES (0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(1,NULL,'next-header,source-address,destination-address',NULL,NULL,NULL,'source-port-number,destination-port-number',NULL,NULL,NULL);
/*!40000 ALTER TABLE `generic-nsf-capabilities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `memory`
--

DROP TABLE IF EXISTS `memory`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `memory` (
  `id` int NOT NULL,
  `capacity` int unsigned DEFAULT NULL,
  `speed` int unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `memory`
--

LOCK TABLES `memory` WRITE;
/*!40000 ALTER TABLE `memory` DISABLE KEYS */;
INSERT INTO `memory` VALUES (1,4096,2667);
/*!40000 ALTER TABLE `memory` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nsf`
--

DROP TABLE IF EXISTS `nsf`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `nsf` (
  `nsf-name` varchar(255) NOT NULL,
  `version` varchar(255) DEFAULT NULL,
  `directional-capabilities` set('unidirectional','bidirectional') DEFAULT NULL,
  `event-capabilities` int DEFAULT NULL,
  `condition-capabilities` int DEFAULT NULL,
  `action-capabilities` int DEFAULT NULL,
  `resolution-strategy-capabilties` set('fmr','lmr','pmre','pmrn') DEFAULT NULL,
  `default-action-capabilities` set('pass','drop','reject','mirror','rate-limit') DEFAULT NULL,
  `nsf-specification` int DEFAULT NULL,
  `nsf-access-info` int DEFAULT NULL,
  PRIMARY KEY (`nsf-name`),
  KEY `event-capabilities` (`event-capabilities`),
  KEY `condition-capabilities` (`condition-capabilities`),
  KEY `action-capabilities` (`action-capabilities`),
  KEY `nsf-specification` (`nsf-specification`),
  KEY `nsf-access-info` (`nsf-access-info`),
  CONSTRAINT `nsf_ibfk_1` FOREIGN KEY (`event-capabilities`) REFERENCES `event-capabilities` (`id`),
  CONSTRAINT `nsf_ibfk_2` FOREIGN KEY (`condition-capabilities`) REFERENCES `condition-capabilities` (`id`),
  CONSTRAINT `nsf_ibfk_3` FOREIGN KEY (`action-capabilities`) REFERENCES `action-capabilities` (`id`),
  CONSTRAINT `nsf_ibfk_4` FOREIGN KEY (`nsf-specification`) REFERENCES `nsf-specification` (`id`),
  CONSTRAINT `nsf_ibfk_5` FOREIGN KEY (`nsf-access-info`) REFERENCES `nsf-access-info` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nsf`
--

LOCK TABLES `nsf` WRITE;
/*!40000 ALTER TABLE `nsf` DISABLE KEYS */;
INSERT INTO `nsf` VALUES ('firewall','1.2.0',NULL,0,1,1,NULL,NULL,1,1),('url-filtering','5.1.2',NULL,0,3,1,NULL,NULL,1,3);
/*!40000 ALTER TABLE `nsf` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nsf-access-info`
--

DROP TABLE IF EXISTS `nsf-access-info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `nsf-access-info` (
  `id` int NOT NULL,
  `ip` varchar(255) DEFAULT NULL,
  `port` int unsigned DEFAULT NULL,
  `management-protocol` enum('RESTCONF','NETCONF') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nsf-access-info`
--

LOCK TABLES `nsf-access-info` WRITE;
/*!40000 ALTER TABLE `nsf-access-info` DISABLE KEYS */;
INSERT INTO `nsf-access-info` VALUES (1,'10.0.0.5',2022,'NETCONF'),(3,'10.0.0.47',2022,'NETCONF');
/*!40000 ALTER TABLE `nsf-access-info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `nsf-specification`
--

DROP TABLE IF EXISTS `nsf-specification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `nsf-specification` (
  `id` int NOT NULL,
  `cpu` int DEFAULT NULL,
  `memory` int DEFAULT NULL,
  `disk` int DEFAULT NULL,
  `bandwidth` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `cpu` (`cpu`),
  KEY `memory` (`memory`),
  KEY `disk` (`disk`),
  KEY `bandwidth` (`bandwidth`),
  CONSTRAINT `nsf-specification_ibfk_1` FOREIGN KEY (`cpu`) REFERENCES `cpu` (`id`),
  CONSTRAINT `nsf-specification_ibfk_2` FOREIGN KEY (`memory`) REFERENCES `memory` (`id`),
  CONSTRAINT `nsf-specification_ibfk_3` FOREIGN KEY (`disk`) REFERENCES `disk` (`id`),
  CONSTRAINT `nsf-specification_ibfk_4` FOREIGN KEY (`bandwidth`) REFERENCES `bandwidth` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `nsf-specification`
--

LOCK TABLES `nsf-specification` WRITE;
/*!40000 ALTER TABLE `nsf-specification` DISABLE KEYS */;
INSERT INTO `nsf-specification` VALUES (1,1,1,1,1);
/*!40000 ALTER TABLE `nsf-specification` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-07-14 10:08:24
