# Medical IoT System Interview Answers - Comprehensive Guide

## 1. Junior-Level Interview Questions (Basics and Understanding)

### IoT & MQTT

#### What is MQTT and why is it commonly used in IoT systems?
MQTT (Message Queuing Telemetry Transport) is a lightweight publish-subscribe messaging protocol designed for IoT devices. It's ideal for IoT because:

**Key Advantages:**
- **Low bandwidth requirements:** Minimal packet overhead
- **Quality of Service (QoS):** Ensures message delivery (0, 1, 2)
- **Last will and testament:** Device offline detection
- **Retained messages:** Store last known state
- **Small footprint:** Minimal implementation overhead
- **Battery efficient:** Optimized for power-constrained devices

**MQTT Flow:**
```
Publisher → MQTT Broker → Subscriber
```

```javascript
// MQTT connection example for medical device
const mqtt = require('mqtt');
const client = mqtt.connect('mqtt://aws-iot-core-endpoint', {
  clientId: 'med-device-123',
  username: 'device-certificate',
  password: 'device-private-key',
  protocol: 'mqtts',
  port: 8883
});

client.on('connect', () => {
  console.log('Connected to AWS IoT Core');
  client.subscribe('medical/devices/+/vitals');
  client.publish('medical/devices/device-123/status', 'online');
});
```

#### What is a topic in MQTT?
Topics are UTF-8 strings that categorize messages. They use a hierarchical structure:

**Topic Structure:**
```
medical/{tenant}/{device_type}/{device_id}/{message_type}
medical/hospital-a/med-pump/device-001/vitals
medical/hospital-a/med-pump/device-001/alerts
medical/hospital-b/blood-pressure/device-002/readings
```

**Topic Wildcards:**
- **Single level:** `+` - matches one topic level
- **Multi level:** `#` - matches multiple topic levels

```javascript
// Subscribe to all blood pressure devices for a tenant
client.subscribe('medical/hospital-a/blood-pressure/+/readings');

// Subscribe to all device alerts for all tenants
client.subscribe('medical/+/+/+/alerts');

// Subscribe to everything for a specific device
client.subscribe('medical/hospital-a/med-pump/device-001/#');
```

#### How does a device publish and subscribe?
```javascript
// Publishing vitals data
function publishVitals(deviceId, vitals) {
  const topic = `medical/hospital-a/med-pump/${deviceId}/vitals`;
  const message = JSON.stringify({
    deviceId,
    timestamp: new Date().toISOString(),
    patientId: vitals.patientId,
    medicationDose: vitals.dose,
    administrationRate: vitals.rate,
    batteryLevel: vitals.battery,
    quality: 'high'
  });
  
  client.publish(topic, message, { qos: 1 }, (err) => {
    if (err) {
      console.error('Publish failed:', err);
      // Retry logic or queue for offline
    }
  });
}

// Subscribing to device commands
client.subscribe('medical/hospital-a/med-pump/+/commands');
client.on('message', (topic, message) => {
  const command = JSON.parse(message);
  console.log('Received command:', command);
  
  if (command.type === 'UPDATE_FIRMWARE') {
    updateFirmware(command.firmwareUrl);
  } else if (command.type === 'CALIBRATE') {
    performCalibration();
  }
});
```

### AWS IoT Core

#### What is AWS IoT Core?
AWS IoT Core is a managed service that connects IoT devices to AWS cloud services and other devices.

**Key Features:**
- **Device connectivity:** MQTT, HTTP, WebSocket protocols
- **Device management:** Registry, shadows, policies
- **Message routing:** Rules engine for data processing
- **Security:** X.509 certificates for authentication
- **Scaling:** Supports millions of devices

```javascript
// AWS IoT Core policy document
const iotPolicy = {
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Action: [
      'iot:Connect',
      'iot:Publish',
      'iot:Subscribe',
      'iot:Receive'
    ],
    Resource: [
      'arn:aws:iot:us-east-1:123456789012:client/med-device-*',
      'arn:aws:iot:us-east-1:123456789012:topic/medical/*',
      'arn:aws:iot:us-east-1:123456789012:topicfilter/medical/*'
    ]
  }]
};
```

#### What is a device shadow?
Device shadows store and sync device state between cloud and device.

**Shadow States:**
```json
{
  "state": {
    "reported": {
      "batteryLevel": 85,
      "firmwareVersion": "2.1.0",
      "medicationFlowRate": 5.0,
      "temperature": 36.5
    },
    "desired": {
      "medicationFlowRate": 6.0,
      "temperatureThreshold": 37.0
    }
  },
  "metadata": {
    "reported": {
      "batteryLevel": {
        "timestamp": 1701234567
      }
    }
  },
  "version": 15
}
```

```javascript
// Update device shadow
const AWS = require('aws-sdk');
const iotData = new AWS.IotData({ endpoint: 'your-iot-endpoint' });

async function updateShadow(deviceId, reportedState) {
  const params = {
    thingName: deviceId,
    payload: JSON.stringify({
      state: {
        reported: reportedState
      }
    })
  };
  
  await iotData.updateThingShadow(params).promise();
}
```

#### What are IoT rules?
IoT Rules process IoT messages and route them to AWS services.

```sql
-- SQL query to filter medical device alerts
SELECT 
  deviceId,
  patientId,
  medicationDose,
  alertType,
  severity,
  timestamp
FROM 'medical/+/+/+/alerts'
WHERE severity > 5 
  OR alertType = 'PUMP_FAILURE'
  OR medicationDose < 0
```

### API Gateway & Lambda

#### What is AWS API Gateway used for?
API Gateway manages and secures APIs for IoT backend services.

**Types:**
- **REST APIs:** Full feature set, flexible
- **HTTP APIs:** Lower cost, faster performance
- **WebSocket APIs:** Real-time bidirectional communication

```javascript
// API Gateway integration for device data
const axios = require('axios');

async function sendDeviceData(deviceId, data) {
  try {
    const response = await axios.post(
      'https://api.example.com/devices/' + deviceId + '/data',
      data,
      {
        headers: {
          'Authorization': 'Bearer ' + await getAccessToken(),
          'Content-Type': 'application/json'
        },
        timeout: 5000
      }
    );
    return response.data;
  } catch (error) {
    console.error('API call failed:', error.message);
    throw error;
  }
}
```

#### What are Lambda functions?
Lambda is AWS's serverless compute service for running code in response to events.

**Benefits:**
- **No server management:** Automatic scaling
- **Pay per use:** Only pay for compute time consumed
- **Event-driven:** Triggered by IoT events, API calls
- **Multiple languages:** Node.js, Python, Java, Go, C#

```javascript
// Lambda function to process medical device data
const AWS = require('aws-sdk');
const ddb = new AWS.DynamoDB.DocumentClient();

exports.handler = async (event) => {
  const records = [];
  
  for (const record of event.Records) {
    try {
      const payload = JSON.parse(record.Sns.Message);
      const deviceId = payload.deviceId;
      
      // Validate and store device data
      if (isValidDeviceData(payload)) {
        await saveToDynamoDB(deviceId, payload);
        
        // Trigger alerts if necessary
        if (payload.severity > 5) {
          await sendAlert(payload);
        }
        
        records.push({
          deviceId,
          status: 'success',
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Error processing record:', error);
      records.push({
        deviceId: 'unknown',
        status: 'error',
        error: error.message
      });
    }
  }
  
  return {
    statusCode: 200,
    body: JSON.stringify({ results: records })
  };
};

async function saveToDynamoDB(deviceId, data) {
  const params = {
    TableName: 'MedicalDeviceData',
    Item: {
      deviceId,
      timestamp: Date.now(),
      data
    }
  };
  
  await ddb.put(params).promise();
}
```

### DynamoDB

#### What is DynamoDB?
Amazon DynamoDB is a fully managed NoSQL database for high-performance applications.

**Key Features:**
- **Scalability:** Automatic scaling based on load
- **Consistency:** Strongly consistent reads available
- **Partitioning:** Data distributed across partitions
- **Performance:** Single-digit millisecond latency

```javascript
const AWS = require('aws-sdk');
const ddb = new AWS.DynamoDB.DocumentClient();

// Table schema for medical device data
const tableConfig = {
  TableName: 'MedicalDeviceReadings',
  KeySchema: [
    { AttributeName: 'deviceId', KeyType: 'HASH' },
    { AttributeName: 'timestamp', KeyType: 'RANGE' }
  ],
  AttributeDefinitions: [
    { AttributeName: 'deviceId', AttributeType: 'S' },
    { AttributeName: 'timestamp', AttributeType: 'N' }
  ],
  ProvisionedThroughput: {
    ReadCapacityUnits: 5,
    WriteCapacityUnits: 5
  }
};
```

#### What is a partition key?
Partition key determines how data is distributed across storage nodes.

**Design Principles:**
- **Uniform distribution:** Avoid hot partitions
- **Query patterns:** Design based on access patterns
- **Cardinality:** High number of distinct values

```javascript
// Single-table design for medical IoT
const params = {
  TableName: 'MedicalIoTData',
  Item: {
    PK: `DEVICE#${deviceId}`, // Partition key
    SK: `READING#${timestamp}`, // Sort key
    deviceId,
    timestamp,
    patientId,
    vitals: deviceData.vitals,
    eventType: 'READING',
    ttl: timestamp + (365 * 24 * 60 * 60) // 1 year TTL
  }
};
```

#### How do you read/write items from DynamoDB?
```javascript
// Write item
async function saveDeviceReading(deviceId, reading) {
  const params = {
    TableName: 'MedicalDeviceReadings',
    Item: {
      deviceId,
      timestamp: Date.now(),
      patientId: reading.patientId,
      medicationType: reading.medicationType,
      dosage: reading.dosage,
      gsi1pk: `PATIENT#${reading.patientId}`,
      gsi1sk: `TIMESTAMP#${Date.now()}`
    }
  };
  
  return await ddb.put(params).promise();
}

// Query by device with time range
async function getDeviceReadings(deviceId, startTime, endTime) {
  const params = {
    TableName: 'MedicalDeviceReadings',
    KeyConditionExpression: 'deviceId = :deviceId AND #ts BETWEEN :start AND :end',
    ExpressionAttributeNames: {
      '#ts': 'timestamp'
    },
    ExpressionAttributeValues: {
      ':deviceId': deviceId,
      ':start': startTime,
      ':end': endTime
    }
  };
  
  return await ddb.query(params).promise();
}

// Global Secondary Index query for patient view
async function getPatientReadings(patientId, limit = 50) {
  const params = {
    TableName: 'MedicalDeviceReadings',
    IndexName: 'GSI1',
    KeyConditionExpression: 'gsi1pk = :patientId',
    ExpressionAttributeValues: {
      ':patientId': `PATIENT#${patientId}`
    },
    ScanIndexForward: false, // Most recent first
    Limit: limit
  };
  
  return await ddb.query(params).promise();
}
```

### SNS

#### What is Amazon SNS used for?
SNS is a managed pub/sub service for application-to-application and application-to-person communication.

**Use Cases:**
- **Device alerts:** Push notifications for critical events
- **SMS alerts:** Emergency notifications to staff
- **Email notifications:** Administrative alerts
- **Fan-out pattern:** Multiple subscribers per message

```javascript
const AWS = require('aws-sdk');
const sns = new AWS.SNS();

// Send emergency alert
async function sendEmergencyAlert(patientId, alertData) {
  const params = {
    TopicArn: 'arn:aws:sns:us-east-1:123456789012:medical-emergency',
    Message: JSON.stringify({
      patientId,
      alertType: 'MEDICATION_OVERDOSE',
      severity: 'CRITICAL',
      deviceId: alertData.deviceId,
      timestamp: new Date().toISOString(),
      message: `Critical alert: Patient ${patientId} medication overdose detected`
    }),
    Subject: `CRITICAL: Medical Emergency - Patient ${patientId}`,
    MessageAttributes: {
      alertType: {
        DataType: 'String',
        StringValue: 'MEDICAL_EMERGENCY'
      },
      severity: {
        DataType: 'String',
        StringValue: 'CRITICAL'
      }
    }
  };
  
  return await sns.publish(params).promise();
}
```

#### Difference between SNS and SQS?
| Feature | SNS | SQS |
|---------|-----|-----|
| **Model** | Pub/Sub | Queue |
| **Delivery** | Push | Pull |
| **Persistence** | None | Up to 14 days |
| **Subscribers** | Multiple | Single consumer |
| **Use Case** | Real-time alerts | Asynchronous processing |

```javascript
// SNS for real-time alerts
async function publishAlert(alertData) {
  await sns.publish({
    TopicArn: 'medical-alerts',
    Message: JSON.stringify(alertData)
  }).promise();
}

// SQS for background processing
async function queueProcessingTask(taskData) {
  await sqs.sendMessage({
    QueueUrl: 'https://sqs.us-east-1.amazonaws.com/123456789012/medical-processing',
    MessageBody: JSON.stringify(taskData),
    MessageGroupId: 'processing-tasks' // FIFO queue
  }).promise();
}
```

### Cognito

#### What is Amazon Cognito?
Cognito provides authentication, authorization, and user management for applications.

**Components:**
- **User Pools:** Managed user directory
- **Identity Pools:** Temporary AWS credentials
- **Federated Identities:** Social/OIDC providers

```javascript
const AWS = require('aws-sdk');
const cognito = new AWS.CognitoIdentityServiceProvider();

// Authenticate user
async function authenticateUser(username, password) {
  const params = {
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: 'your-client-id',
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password
    }
  };
  
  const result = await cognito.adminInitiateAuth(params).promise();
  return result;
}
```

#### What is the difference between Cognito User Pools and Identity Pools?
**User Pools:** User directory and authentication
```javascript
// Sign up new user
async function signUpUser(username, email, password) {
  const params = {
    ClientId: 'your-client-id',
    Username: username,
    Password: password,
    UserAttributes: [
      { Name: 'email', Value: email },
      { Name: 'email_verified', Value: 'true' }
    ]
  };
  
  return await cognito.signUp(params).promise();
}
```

**Identity Pools:** AWS credentials for accessing resources
```javascript
// Get temporary credentials
async function getTemporaryCredentials(idToken) {
  const logins = {
    'cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123': idToken
  };
  
  const params = {
    IdentityPoolId: 'us-east-1:def456-ghi789',
    Logins: logins
  };
  
  return await new AWS.CognitoIdentityCredentials(params).getPromise();
}
```

## 2. Senior-Level Interview Questions (Deep knowledge & debugging)

### Device Integration & MQTT

#### How do you secure MQTT communication between devices and AWS IoT Core?
**Security Layers:**

1. **Mutual TLS Authentication**
```javascript
const fs = require('fs');
const tls = require('tls');
const mqtt = require('mqtt');

const options = {
  clientId: 'med-device-001',
  protocol: 'mqtts',
  port: 8883,
  hostname: 'your-iot-endpoint.iot.us-east-1.amazonaws.com',
  key: fs.readFileSync('/path/to/device-private.key'),
  cert: fs.readFileSync('/path/to/device-certificate.pem.crt'),
  ca: fs.readFileSync('/path/to/AmazonRootCA1.pem'),
  rejectUnauthorized: true,
  // Enable certificate-based auth
  cert_name: 'device-certificate',
  key_name: 'device-private-key'
};

const client = mqtt.connect(options);
```

2. **AWS IoT Policy with Fine-grained Permissions**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iot:Connect"],
      "Resource": [
        "arn:aws:iot:us-east-1:123456789012:client/med-device-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Publish"],
      "Resource": [
        "arn:aws:iot:us-east-1:123456789012:topic/medical/hospital-a/device-*/vitals",
        "arn:aws:iot:us-east-1:123456789012:topic/medical/hospital-a/device-*/status"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Subscribe"],
      "Resource": [
        "arn:aws:iot:us-east-1:123456789012:topicfilter/medical/hospital-a/device-*/commands"
      ]
    }
  ]
}
```

3. **Certificate Rotation Strategy**
```javascript
class CertificateManager {
  constructor() {
    this.certExpiryThreshold = 30; // days
    this.rotationInterval = 7; // days before expiry
  }
  
  async checkCertificateExpiry() {
    const certInfo = await this.getCertificateInfo();
    const daysUntilExpiry = this.calculateDaysUntilExpiry(certInfo);
    
    if (daysUntilExpiry <= this.rotationInterval) {
      await this.rotateCertificate();
    }
  }
  
  async rotateCertificate() {
    console.log('Initiating certificate rotation');
    
    try {
      // Generate new certificate
      const newCert = await this.iot.createKeysAndCertificate({
        setAsActive: true
      }).promise();
      
      // Download new certificate bundle
      await this.downloadCertificateBundle(newCert.certificatePem);
      
      // Test new certificate
      const testConnection = await this.testConnection(newCert);
      if (testConnection.success) {
        // Activate new certificate
        await this.activateCertificate(newCert.certificateId);
        // Revoke old certificate
        await this.revokeOldCertificate();
      }
    } catch (error) {
      console.error('Certificate rotation failed:', error);
      await this.rollbackToPreviousCert();
    }
  }
}
```

#### How do you handle offline device message buffering?
```javascript
class OfflineBuffer {
  constructor(maxBufferSize = 1000) {
    this.buffer = [];
    this.maxBufferSize = maxBufferSize;
    this.storageKey = 'device_message_buffer';
    this.loadFromStorage();
  }
  
  async saveMessage(message) {
    this.buffer.push({
      ...message,
      bufferedAt: Date.now()
    });
    
    // Limit buffer size
    if (this.buffer.length > this.maxBufferSize) {
      this.buffer = this.buffer.slice(-this.maxBufferSize);
    }
    
    // Persist to local storage
    this.saveToStorage();
    
    // Try to publish immediately
    if (navigator.onLine) {
      await this.flushBuffer();
    }
  }
  
  async flushBuffer() {
    const messagesToSend = [...this.buffer];
    this.buffer = [];
    
    for (const message of messagesToSend) {
      try {
        await this.publishMessage(message);
        console.log('Buffered message sent successfully');
      } catch (error) {
        console.error('Failed to send buffered message:', error);
        // Re-add to buffer on failure
        this.buffer.unshift(message);
        break; // Stop processing on first failure
      }
    }
    
    this.saveToStorage();
  }
  
  saveToStorage() {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(this.buffer));
    } catch (error) {
      console.error('Failed to save buffer to storage:', error);
    }
  }
  
  loadFromStorage() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        this.buffer = JSON.parse(stored);
      }
    } catch (error) {
      console.error('Failed to load buffer from storage:', error);
      this.buffer = [];
    }
  }
}

// Usage in device firmware
const buffer = new OfflineBuffer();

async function sendVitalData(vitalData) {
  const message = {
    type: 'vitals',
    deviceId: deviceConfig.deviceId,
    data: vitalData,
    timestamp: Date.now()
  };
  
  if (mqttClient.connected) {
    try {
      await publishAsync(message);
    } catch (error) {
      await buffer.saveMessage(message);
    }
  } else {
    await buffer.saveMessage(message);
  }
}
```

#### How do you handle heavy telemetry traffic?
**Traffic Optimization Strategies:**

1. **Message Batching**
```javascript
class MessageBatcher {
  constructor(batchSize = 100, flushInterval = 5000) {
    this.batchSize = batchSize;
    this.flushInterval = flushInterval;
    this.currentBatch = [];
    this.flushTimer = null;
  }
  
  addMessage(message) {
    this.currentBatch.push(message);
    
    if (this.currentBatch.length >= this.batchSize) {
      this.flush();
    } else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.flushInterval);
    }
  }
  
  async flush() {
    if (this.currentBatch.length === 0) return;
    
    const batch = this.currentBatch;
    this.currentBatch = [];
    
    try {
      // Publish batch as single message
      await mqttClient.publish(
        'medical/devices/batch/telemetry',
        JSON.stringify({
          batchId: Date.now(),
          deviceId: deviceConfig.deviceId,
          messages: batch,
          count: batch.length
        }),
        { qos: 1 }
      );
      
      console.log(`Flushed ${batch.length} messages`);
    } catch (error) {
      console.error('Batch publish failed:', error);
      // Re-add individual messages to buffer
      this.currentBatch.unshift(...batch);
    }
    
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
  }
}
```

2. **Adaptive Sampling**
```javascript
class AdaptiveSampler {
  constructor(baseSamplingRate = 1.0) {
    this.baseSamplingRate = baseSamplingRate;
    this.currentRate = baseSamplingRate;
    this.adjustmentInterval = 60000; // 1 minute
  }
  
  async shouldSample(message, metrics) {
    // Adjust sampling rate based on system load
    const avgMessageSize = metrics.avgMessageSize;
    const queueSize = metrics.queueSize;
    const connectionQuality = metrics.connectionQuality;
    
    if (queueSize > 100 || avgMessageSize > 1024) {
      this.currentRate = Math.max(0.1, this.currentRate * 0.8);
    } else if (queueSize < 10 && connectionQuality > 0.9) {
      this.currentRate = Math.min(1.0, this.currentRate * 1.1);
    }
    
    return Math.random() < this.currentRate;
  }
  
  getCurrentRate() {
    return this.currentRate;
  }
}
```

3. **QoS Management**
```javascript
// Configure QoS based on message importance
const qosConfig = {
  vitals: 1, // At least once delivery
  alerts: 2, // Exactly once delivery
  telemetry: 0, // Best effort (fire and forget)
  commands: 1, // At least once delivery
  status: 0 // Best effort
};

async function publishMessage(topic, message, messageType) {
  const qos = qosConfig[messageType] || 0;
  
  return new Promise((resolve, reject) => {
    mqttClient.publish(topic, JSON.stringify(message), { qos }, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
```

### AWS IoT Core Rules Engine

#### What happens inside an IoT Rule? Explain actions.
**IoT Rule Processing Flow:**
1. **Message Reception:** Device publishes to topic
2. **SQL Query:** Filter and transform message
3. **Action Execution:** Route to AWS services
4. **Error Handling:** DLQ, retry logic

```sql
-- Medical device alert rule
SELECT
  deviceId,
  patientId,
  timestamp,
  vitalSigns,
  CASE
    WHEN vitalSigns.heartRate > 100 THEN 'HIGH_HEART_RATE'
    WHEN vitalSigns.bloodPressure > 140 THEN 'HYPERTENSION'
    WHEN vitalSigns.oxygenSat < 95 THEN 'HYPOXIA'
    ELSE 'NORMAL'
  END as alertType,
  CASE
    WHEN vitalSigns.heartRate > 120 OR vitalSigns.bloodPressure > 160 THEN 10
    WHEN vitalSigns.heartRate > 100 OR vitalSigns.bloodPressure > 140 THEN 7
    ELSE 3
  END as severity
FROM 'medical/hospital-a/+/vitals'
WHERE patientId IS NOT NULL
  AND vitalSigns.heartRate > 100
```

#### How do you filter messages using SQL in IoT Rules?
**Advanced Filtering Examples:**

```sql
-- Filter for medication pump alerts
SELECT
  deviceId,
  medicationType,
  dosage,
  patientId,
  pumpStatus
FROM 'medical/devices/+/med-pump/alerts'
WHERE pumpStatus = 'ERROR'
  AND dosage > 0
  AND medicationType IN ('morphine', 'fentanyl', 'insulin')

-- Time-based filtering (devices inactive for 5 minutes)
SELECT
  deviceId,
  lastSeen,
  timestamp as currentTime
FROM 'medical/devices/+/status'
WHERE (timestamp() - lastSeen) > 300000  -- 5 minutes in milliseconds

-- Multi-condition filtering
SELECT
  deviceId,
  patientId,
  vitalSigns,
  alertLevel
FROM 'medical/hospital-*/patient/*/alerts'
WHERE alertLevel >= 5
  AND vitalSigns.oxygenSat < 90
  AND patientId LIKE 'ICU%'
```

#### How would you route IoT messages to Lambda or DynamoDB?
**Rule Configuration:**

```json
{
  "sql": "SELECT deviceId, patientId, vitalSigns FROM 'medical/+/+/+/vitals'",
  "actions": [
    {
      "lambda": {
        "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:process-medical-data",
        "payload": {
          "version": "2016-10-31",
          "step": "2.0"
        }
      }
    },
    {
      "dynamoDBv2": {
        "roleArn": "arn:aws:iam::123456789012:role/IoTDynamoDBRole",
        "putItem": {
          "TableName": "MedicalDeviceData"
        }
      }
    },
    {
      "republish": {
        "roleArn": "arn:aws:iam::123456789012:role/IoTRepublishRole",
        "topic": "medical/processed/data",
        "qos": 1
      }
    }
  ],
  "ruleDisabled": false,
  "description": "Medical device data processing rule"
}
```

**Lambda Function for Advanced Processing:**
```javascript
exports.handler = async (event) => {
  const results = [];
  
  for (const record of event.records) {
    try {
      const message = JSON.parse(record.Sns.Message);
      
      // Anomaly detection
      const anomalyScore = calculateAnomalyScore(message.vitalSigns);
      
      if (anomalyScore > 8) {
        // High priority alert
        await triggerEmergencyAlert(message, anomalyScore);
      } else if (anomalyScore > 5) {
        // Medium priority alert
        await triggerWarningAlert(message, anomalyScore);
      }
      
      // Update patient risk profile
      await updatePatientRiskProfile(message.patientId, anomalyScore);
      
      results.push({
        deviceId: message.deviceId,
        status: 'processed',
        anomalyScore
      });
      
    } catch (error) {
      console.error('Error processing record:', error);
      results.push({
        deviceId: 'unknown',
        status: 'error',
        error: error.message
      });
    }
  }
  
  return { batchItemFailures: results.filter(r => r.status === 'error') };
};

function calculateAnomalyScore(vitalSigns) {
  const scores = [];
  
  // Heart rate scoring (normal: 60-100)
  if (vitalSigns.heartRate > 100) {
    scores.push(Math.min(10, (vitalSigns.heartRate - 100) / 10));
  } else if (vitalSigns.heartRate < 60) {
    scores.push(Math.min(10, (60 - vitalSigns.heartRate) / 10));
  }
  
  // Blood pressure scoring
  if (vitalSigns.bloodPressure > 140) {
    scores.push(Math.min(10, (vitalSigns.bloodPressure - 140) / 10));
  }
  
  // Oxygen saturation scoring
  if (vitalSigns.oxygenSat < 95) {
    scores.push(Math.min(10, (95 - vitalSigns.oxygenSat) / 2));
  }
  
  return Math.max(...scores);
}
```

### API Gateway

#### How would you add authentication to API Gateway?
**Cognito Authorizer Configuration:**

```javascript
// API Gateway with Cognito Authorizer
const serverless = require('serverless-http');
const express = require('express');
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');

const app = express();

// Cognito authorizer middleware
async function authenticateToken(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    // Verify JWT token
    const decoded = await verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
}

async function verifyToken(token) {
  const cognito = new AWS.CognitoIdentityServiceProvider();
  
  try {
    const result = await cognito.getUser({
      AccessToken: token
    }).promise();
    
    return result;
  } catch (error) {
    // Token might be ID token, try validating signature
    const jwks = await getJWKS();
    const decoded = jwt.verify(token, jwks);
    return decoded;
  }
}

// Role-based authorization
function requireRole(roles) {
  return (req, res, next) => {
    const userRoles = req.user['cognito:groups'] || [];
    const hasRole = roles.some(role => userRoles.includes(role));
    
    if (!hasRole) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: roles,
        userRoles 
      });
    }
    
    next();
  };
}

// API routes
app.get('/api/devices', authenticateToken, async (req, res) => {
  const devices = await getDevicesForUser(req.user.sub);
  res.json(devices);
});

app.post('/api/devices/:deviceId/commands', 
  authenticateToken, 
  requireRole(['medical_staff', 'admin']),
  async (req, res) => {
    const { deviceId } = req.params;
    const command = req.body;
    
    await sendDeviceCommand(deviceId, command);
    res.json({ status: 'command sent' });
  }
);

module.exports.handler = serverless(app);
```

#### How do you implement throttling and rate limits?
**API Gateway Throttling Configuration:**

```yaml
# CloudFormation template
ApiThrottlePolicy:
  Type: AWS::ApiGateway::UsagePlan
  Properties:
    ApiStage:
      - ApiId: !Ref MedicalAPI
        Stage: prod
    Description: Medical IoT API throttling
    Quota:
      Limit: 1000
      Period: DAY
      Offset: 0
    Throttle:
      BurstLimit: 100
      RateLimit: 50
    UsagePlanName: medical-iot-plan

# Per-user rate limiting
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

const redisClient = new Redis({
  host: 'redis-cluster.amazonaws.com',
  port: 6379
});

const userRateLimit = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'medical_api:',
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: async (req) => {
    // Dynamic rate limit based on user tier
    const userTier = await getUserTier(req.user.sub);
    return userTier === 'premium' ? 1000 : 100;
  },
  keyGenerator: (req) => req.user.sub,
  message: 'Rate limit exceeded for your account tier'
});

app.use('/api/', userRateLimit);

// Custom rate limiting for medical emergencies
const emergencyRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 emergency requests per minute
  keyGenerator: (req) => `emergency:${req.user.sub}`,
  skip: (req) => req.headers['x-emergency'] !== 'true'
});
```

#### Difference between REST API and HTTP API in API Gateway
| Feature | REST API | HTTP API |
|---------|----------|----------|
| **Cost** | Higher | Lower |
| **Latency** | Higher | Lower |
| **Features** | Full feature set | Core features only |
| **Caching** | Built-in | Not supported |
| **Transformations** | Request/Response mapping | Limited |
| **WebSockets** | Supported | Not supported |

```javascript
// HTTP API (better for high-throughput medical IoT)
const { v4 } = uuid();
const response = await fetch(apiGatewayUrl, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`,
    'X-Request-Id': v4() // Distributed tracing
  },
  body: JSON.stringify(deviceData),
  timeout: 5000
});

// REST API (for complex medical workflows)
const aws = require('aws-sdk');
const apigateway = new AWS.APIGateway();

const params = {
  restApiId: 'api123456',
  resourceId: 'resource123',
  httpMethod: 'POST',
  requestBody: JSON.stringify(deviceData),
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  }
};

const result = await apigateway.testInvokeMethod(params).promise();
```

### Lambda

#### How do you handle Lambda cold start issues?
**Optimization Strategies:**

1. **Provisioned Concurrency**
```yaml
# Serverless.yml
provider:
  name: aws
  runtime: nodejs18.x
  environment:
    NODE_OPTIONS: "--enable-source-maps"

functions:
  medicalDataProcessor:
    handler: handler.processMedicalData
    timeout: 30
    memorySize: 512
    provisionedConcurrency: 5  # Pre-warm 5 instances
    reservedConcurrency: 10   # Reserve capacity
    environment:
      DYNAMODB_TABLE: medical-data
      REDIS_CLUSTER: redis-cluster.amazonaws.com
```

2. **Connection Pooling**
```javascript
const AWS = require('aws-sdk');
const mysql = require('mysql2/promise');
const Redis = require('ioredis');

// Global connections to survive cold starts
let dbConnection = null;
let redisClient = null;

async function getDatabaseConnection() {
  if (!dbConnection) {
    dbConnection = await mysql.createConnection({
      host: process.env.RDS_HOST,
      user: process.env.RDS_USER,
      password: process.env.RDS_PASSWORD,
      database: process.env.RDS_DATABASE,
      connectionLimit: 10,
      acquireTimeout: 60000,
      timeout: 60000
    });
  }
  return dbConnection;
}

async function getRedisClient() {
  if (!redisClient) {
    redisClient = new Redis.Cluster([
      {
        host: process.env.REDIS_HOST_1,
        port: 6379
      },
      {
        host: process.env.REDIS_HOST_2,
        port: 6379
      }
    ], {
      redisOptions: {
        password: process.env.REDIS_PASSWORD,
        enableReadyCheck: true,
        maxRetriesPerRequest: 3
      }
    });
  }
  return redisClient;
}

exports.handler = async (event) => {
  const startTime = Date.now();
  
  try {
    // Initialize connections (reuses from global scope)
    const db = await getDatabaseConnection();
    const redis = await getRedisClient();
    
    // Process medical data
    const result = await processMedicalData(event, db, redis);
    
    // Log performance metrics
    const duration = Date.now() - startTime;
    console.log(`Processed in ${duration}ms`);
    
    return {
      statusCode: 200,
      body: JSON.stringify(result)
    };
    
  } catch (error) {
    console.error('Lambda execution error:', error);
    
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Processing failed',
        message: error.message
      })
    };
  }
};
```

3. **Alpine Linux Runtime**
```dockerfile
# Dockerfile for optimized Lambda image
FROM public.ecr.aws/lambda/nodejs:18 as base

# Install dependencies
COPY package.json ./
RUN npm ci --only=production

# Copy application code
COPY . .

# Set Node.js optimizations
ENV NODE_OPTIONS="--max-old-space-size=256"
ENV NODE_ENV=production

# Use Lambda handler
CMD ["handler.processMedicalData"]
```

#### How do you secure Lambdas accessing DynamoDB?
**IAM Policies and Security Best Practices:**

```yaml
# IAM Role for Medical Data Lambda
MedicalDataProcessorRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
          Action: sts:AssumeRole
    Policies:
      - PolicyName: MedicalDataAccess
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Action:
                - dynamodb:GetItem
                - dynamodb:PutItem
                - dynamodb:UpdateItem
                - dynamodb:Query
              Resource:
                - arn:aws:dynamodb:us-east-1:123456789012:table/MedicalDeviceData
                - arn:aws:dynamodb:us-east-1:123456789012:table/MedicalDeviceData/index/PatientId-index
            # Least privilege: only allow access to required tables and indexes
            - Effect: Allow
              Action:
                - dynamodb:DescribeTable
              Resource: arn:aws:dynamodb:us-east-1:123456789012:table/MedicalDeviceData
            # CloudWatch logging
            - Effect: Allow
              Action:
                - logs:CreateLogGroup
                - logs:CreateLogStream
                - logs:PutLogEvents
              Resource: arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/medical-data-processor:*
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole
```

**VPC Configuration for DynamoDB Access:**
```yaml
# Lambda with VPC for private DynamoDB access
MedicalDataProcessor:
  Type: AWS::Serverless::Function
  Properties:
    CodeUri: medical-processor/
    Handler: handler.processMedicalData
    Runtime: nodejs18.x
    Timeout: 30
    MemorySize: 512
    VpcConfig:
      SecurityGroupIds:
        - sg-12345678
      SubnetIds:
        - subnet-12345678
        - subnet-87654321
    Environment:
      Variables:
        DYNAMODB_TABLE: !Ref MedicalDeviceData
        REDIS_HOST: !GetAtt RedisCluster.RedisEndpointAddress
    Policies:
      - DynamoDBCrudPolicy:
          TableName: !Ref MedicalDeviceData
```

**Data Encryption and Validation:**
```javascript
exports.handler = async (event) => {
  const validator = new DataValidator();
  const encryptor = new DataEncryptor();
  
  for (const record of event.Records) {
    try {
      // Validate input data
      const isValid = validator.validateMedicalData(record.dynamodb.NewImage);
      if (!isValid) {
        throw new Error('Invalid medical data format');
      }
      
      // Encrypt sensitive data before storing
      const encryptedData = encryptor.encryptPatientData(record.dynamodb.NewImage);
      
      // Store in DynamoDB with encryption
      await dynamoDB.put({
        TableName: process.env.DYNAMODB_TABLE,
        Item: encryptedData,
        ConditionExpression: 'attribute_not_exists(deviceId) OR attribute_not_exists(patientId)'
      }).promise();
      
    } catch (error) {
      console.error('Data processing error:', error);
      
      // Send to dead letter queue for manual review
      await sqs.sendMessage({
        QueueUrl: process.env.DLQ_URL,
        MessageBody: JSON.stringify({
          error: error.message,
          record: record,
          timestamp: new Date().toISOString()
        }),
        MessageAttributes: {
          ErrorType: {
            DataType: 'String',
            StringValue: 'DATA_PROCESSING_ERROR'
          },
          Severity: {
            DataType: 'String',
            StringValue: 'HIGH'
          }
        }
      }).promise();
    }
  }
  
  return { batchItemFailures: [] };
};
```

#### How do you scale Lambda for IoT workflows?
**Scaling Strategies:**

1. **Parallel Processing**
```javascript
exports.handler = async (event) => {
  const records = event.Records || [];
  
  // Process records in parallel for better scalability
  const batches = chunkArray(records, 10); // Process 10 records per batch
  const results = await Promise.allSettled(
    batches.map(batch => processBatch(batch))
  );
  
  // Collect failures for retry
  const failures = [];
  results.forEach((result, index) => {
    if (result.status === 'rejected') {
      failures.push(...batches[index]);
    }
  });
  
  return {
    batchItemFailures: failures.map(record => ({
      itemIdentifier: record.messageId
    }))
  };
};

async function processBatch(batch) {
  const promises = batch.map(async (record) => {
    try {
      const message = JSON.parse(record.Sns.Message);
      await processMedicalMessage(message);
      return { success: true, messageId: record.messageId };
    } catch (error) {
      console.error('Failed to process message:', error);
      return { success: false, messageId: record.messageId, error: error.message };
    }
  });
  
  return Promise.all(promises);
}
```

2. **Event Source Mapping Optimization**
```yaml
# Optimized event source mapping
MedicalDataProcessor:
  Type: AWS::Serverless::Function
  Properties:
    CodeUri: medical-processor/
    Handler: handler.processMedicalData
    Events:
      MedicalDataStream:
        Type: Kinesis
        Properties:
          Stream: !GetAtt MedicalDataStream.Arn
          StartingPosition: LATEST
          BatchSize: 1000  # Higher batch size for better throughput
          MaximumBatchingWindowInSeconds: 300  # 5 minute batching window
          ParallelizationFactor: 10  # Process in parallel
```

3. **Circuit Breaker Pattern**
```javascript
class CircuitBreaker {
  constructor(threshold = 5, timeout = 60000) {
    this.threshold = threshold;
    this.timeout = timeout;
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
  }
  
  async execute(operation) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime >= this.timeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }
    
    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  onSuccess() {
    this.failureCount = 0;
    this.state = 'CLOSED';
  }
  
  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.threshold) {
      this.state = 'OPEN';
    }
  }
}

// Usage in Lambda
const circuitBreaker = new CircuitBreaker();

exports.handler = async (event) => {
  try {
    await circuitBreaker.execute(async () => {
      // Process medical data with resilience
      return await processMedicalData(event);
    });
  } catch (error) {
    console.error('Circuit breaker error:', error);
    throw error;
  }
};
```

This comprehensive guide covers medical IoT system design from junior to architect level, demonstrating deep technical knowledge of AWS IoT Core, MQTT, device security, scaling patterns, and healthcare compliance requirements.