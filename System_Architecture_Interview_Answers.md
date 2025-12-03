# System Architecture Interview Answers - Integrated IoT Platform

## Architecture Overview

Based on your provided architecture diagram, I'll demonstrate deep understanding of your integrated IoT platform that combines three core systems:

### 1. Medical IoT System (Pillcase Devices)
### 2. Healthcare Web/Mobile Application
### 3. Video Analytics & Security System

## 1. Medical IoT System Architecture - Pillcase Devices

### System Components Analysis
```
Medical Device Layer → IoT Core → Event Processing → Healthcare App
      ↓                    ↓              ↓              ↓
   Pillcase n         MQTT Protocol   Lambda      Web/Mobile App
   Devices           IoT Rules        EventBridge   Patient Dashboard
   MQTT              Device Shadow    SNS          Medication Alerts
```

### How would you design the pillcase device communication system?

#### Device-to-Cloud Communication
```javascript
// Pillcase device MQTT communication
class PillcaseDevice {
  constructor(deviceConfig) {
    this.deviceId = deviceConfig.id;
    this.patientId = deviceConfig.patientId;
    this.mqttClient = null;
    this.connectionState = 'disconnected';
    this.buffer = [];
  }
  
  async initialize() {
    // Connect to AWS IoT Core with mutual TLS
    const connectionParams = {
      clientId: `pillcase-${this.deviceId}`,
      protocol: 'mqtts',
      port: 8883,
      host: process.env.IOT_ENDPOINT,
      keyPath: `/certs/${this.deviceId}/private.key`,
      certPath: `/certs/${this.deviceId}/certificate.pem.crt`,
      caPath: '/certs/AmazonRootCA1.pem',
      rejectUnauthorized: true
    };
    
    this.mqttClient = mqtt.connect(connectionParams);
    
    this.mqttClient.on('connect', () => {
      console.log(`Pillcase ${this.deviceId} connected to IoT Core`);
      this.connectionState = 'connected';
      
      // Subscribe to command topics
      this.subscribeToCommands();
      
      // Publish device status
      this.publishDeviceStatus('online');
      
      // Flush any buffered messages
      this.flushBuffer();
    });
    
    this.mqttClient.on('offline', () => {
      this.connectionState = 'offline';
      this.startBuffering();
    });
    
    this.mqttClient.on('error', (error) => {
      console.error(`Pillcase ${this.deviceId} connection error:`, error);
      this.handleConnectionError(error);
    });
  }
  
  // Report medication adherence
  async reportMedicationIntake(medicationData) {
    const message = {
      deviceId: this.deviceId,
      patientId: this.patientId,
      timestamp: Date.now(),
      medicationId: medicationData.medicationId,
      dosage: medicationData.dosage,
      intakeTime: medicationData.intakeTime,
      status: 'taken',
      deviceBattery: this.getBatteryLevel(),
      location: this.getLocation(),
      verificationMethod: medicationData.method // RFID, weight sensor, etc.
    };
    
    const topic = `medical/devices/${this.deviceId}/medication_intake`;
    
    if (this.connectionState === 'connected') {
      await this.publishWithQoS(topic, JSON.stringify(message), 1);
    } else {
      this.bufferMessage(message);
    }
  }
  
  // Device shadow updates
  async updateDeviceShadow(desiredState) {
    const shadowUpdate = {
      state: {
        desired: {
          medicationSchedule: desiredState.schedule,
          reminderEnabled: desiredState.reminders,
          batteryThreshold: desiredState.batteryThreshold
        }
      },
      metadata: {
        device: {
          deviceId: { timestamp: Date.now() }
        }
      },
      version: Date.now()
    };
    
    // Update via IoT Shadow service
    const iot = new AWS.IotData({
      endpoint: process.env.IOT_ENDPOINT
    });
    
    const params = {
      thingName: this.deviceId,
      payload: JSON.stringify(shadowUpdate)
    };
    
    await iot.updateThingShadow(params).promise();
  }
  
  // Handle cloud commands
  subscribeToCommands() {
    const commandTopic = `medical/devices/${this.deviceId}/commands`;
    
    this.mqttClient.subscribe(commandTopic, { qos: 1 }, (err) => {
      if (!err) {
        console.log(`Subscribed to commands for ${this.deviceId}`);
      }
    });
    
    this.mqttClient.on('message', (topic, message) => {
      const command = JSON.parse(message.toString());
      this.processCommand(command);
    });
  }
  
  async processCommand(command) {
    switch (command.type) {
      case 'UPDATE_SCHEDULE':
        await this.updateMedicationSchedule(command.schedule);
        break;
      case 'TRIGGER_REMINDER':
        await this.triggerMedicationReminder(command.medicationId);
        break;
      case 'FACTORY_RESET':
        await this.factoryReset();
        break;
      case 'PING':
        await this.respondToPing();
        break;
      default:
        console.log(`Unknown command: ${command.type}`);
    }
  }
  
  // Message buffering for offline scenarios
  bufferMessage(message) {
    this.buffer.push({
      ...message,
      bufferedAt: Date.now()
    });
    
    // Limit buffer size to prevent memory issues
    if (this.buffer.length > 1000) {
      this.buffer = this.buffer.slice(-500); // Keep last 500 messages
    }
  }
  
  async flushBuffer() {
    if (this.buffer.length === 0) return;
    
    console.log(`Flushing ${this.buffer.length} buffered messages`);
    
    const messagesToSend = [...this.buffer];
    this.buffer = [];
    
    for (const message of messagesToSend) {
      try {
        const topic = `medical/devices/${this.deviceId}/medication_intake`;
        await this.publishWithQoS(topic, JSON.stringify(message), 1);
      } catch (error) {
        console.error('Failed to send buffered message:', error);
        // Re-add failed message to buffer
        this.buffer.unshift(message);
        break;
      }
    }
  }
}

// IoT Rules Engine for pillcase data processing
const iotRules = [
  {
    name: 'MedicationAdherenceRule',
    sql: `
      SELECT 
        deviceId,
        patientId,
        medicationId,
        dosage,
        intakeTime,
        status,
        timestamp
      FROM 'medical/devices/+/medication_intake'
      WHERE status = 'taken'
    `,
    actions: [
      {
        lambda: {
          functionArn: 'arn:aws:lambda:us-east-1:123456789012:function:ProcessMedicationAdherence',
          payload: {
            version: '2016-10-31'
          }
        }
      },
      {
        dynamoDBv2: {
          roleArn: 'arn:aws:iam::123456789012:role/IoTDynamoDBRole',
          putItem: {
            TableName: 'MedicationAdherenceData'
          }
        }
      }
    ]
  },
  {
    name: 'MissedDoseAlertRule',
    sql: `
      SELECT 
        deviceId,
        patientId,
        timestamp as expectedTime,
        medicationId
      FROM 'medical/devices/+/medication_schedule'
      WHERE scheduled_time < (timestamp() - 900000)  -- 15 minutes overdue
        AND NOT EXISTS (
          SELECT 1 FROM 'medical/devices/+/medication_intake' 
          WHERE medicationId = ${medicationId} 
          AND intakeTime > scheduled_time
        )
    `,
    actions: [
      {
        sns: {
          targetArn: 'arn:aws:sns:us-east-1:123456789012:medical-alerts',
          message: {
            alertType: 'MISSED_DOSE',
            priority: 'HIGH',
            deviceId: '${deviceId}',
            patientId: '${patientId}',
            medicationId: '${medicationId}',
            expectedTime: '${expectedTime}'
          },
          subject: 'Missed Medication Alert - ${patientId}'
        }
      }
    ]
  }
];
```

### AWS IoT Core Rules Engine Implementation

```javascript
// Lambda function to process medication adherence data
exports.handler = async (event) => {
  const results = [];
  
  for (const record of event.Records) {
    try {
      const data = JSON.parse(record.Sns.Message);
      
      // Validate medication data
      if (!isValidMedicationData(data)) {
        throw new Error('Invalid medication data format');
      }
      
      // Process adherence pattern
      const adherencePattern = await calculateAdherencePattern(data.patientId, data.medicationId);
      
      // Generate insights
      if (adherencePattern.compliance < 0.8) {
        await triggerCareTeamAlert(data.patientId, adherencePattern);
      }
      
      // Update patient dashboard cache
      await updatePatientCache(data.patientId, {
        lastIntake: data.intakeTime,
        compliance: adherencePattern.compliance,
        missedDoses: adherencePattern.missedDoses
      });
      
      // Store in analytics database
      await storeAnalyticsData({
        patientId: data.patientId,
        deviceId: data.deviceId,
        medicationId: data.medicationId,
        intakeTime: data.intakeTime,
        adherenceScore: adherencePattern.compliance,
        timestamp: Date.now()
      });
      
      results.push({
        deviceId: data.deviceId,
        patientId: data.patientId,
        status: 'processed'
      });
      
    } catch (error) {
      console.error('Processing error:', error);
      results.push({
        deviceId: 'unknown',
        status: 'error',
        error: error.message
      });
    }
  }
  
  return {
    statusCode: 200,
    body: JSON.stringify({ results })
  };
};

function isValidMedicationData(data) {
  return data &&
         data.deviceId &&
         data.patientId &&
         data.medicationId &&
         data.intakeTime &&
         data.status === 'taken';
}
```

## 2. Healthcare Web/Mobile Application Architecture

### API Gateway & Microservices Design

```javascript
// API Gateway configuration for healthcare application
const apiGatewayConfig = {
  routes: [
    {
      path: '/api/patients/{patientId}',
      methods: ['GET', 'PUT'],
      service: 'PatientService',
      auth: 'cognito',
      rateLimit: {
        windowMs: 60000, // 1 minute
        max: 100 // requests per window
      }
    },
    {
      path: '/api/medications',
      methods: ['GET', 'POST'],
      service: 'MedicationService',
      auth: 'cognito',
      rateLimit: {
        windowMs: 60000,
        max: 50
      }
    },
    {
      path: '/api/devices/{deviceId}/commands',
      methods: ['POST'],
      service: 'DeviceCommandService',
      auth: 'cognito',
      rateLimit: {
        windowMs: 60000,
        max: 30
      }
    },
    {
      path: '/api/analytics/adherence',
      methods: ['GET'],
      service: 'AnalyticsService',
      auth: 'cognito',
      rateLimit: {
        windowMs: 60000,
        max: 200
      }
    }
  ]
};

// Lambda function for patient management
const PatientService = {
  async getPatient(patientId, userContext) {
    // Verify access permissions
    if (!await hasPatientAccess(userContext.userId, patientId)) {
      throw new Error('Access denied');
    }
    
    // Get patient data with aggregation
    const [patient, medications, recentAdherence, alerts] = await Promise.all([
      getPatientProfile(patientId),
      getPatientMedications(patientId),
      getRecentAdherence(patientId, 30), // Last 30 days
      getPatientAlerts(patientId)
    ]);
    
    // Aggregate adherence statistics
    const adherenceStats = calculateAdherenceStats(recentAdherence);
    
    return {
      patient,
      medications,
      adherence: {
        recent: recentAdherence,
        statistics: adherenceStats
      },
      alerts: alerts.filter(alert => !alert.resolved)
    };
  },
  
  async updatePatientProfile(patientId, updates, userContext) {
    // Validate permissions
    if (!await hasWritePermission(userContext.userId, patientId)) {
      throw new Error('Write access denied');
    }
    
    // Validate data integrity
    const validationResult = validatePatientUpdates(updates);
    if (!validationResult.isValid) {
      throw new Error(`Validation failed: ${validationResult.errors.join(', ')}`);
    }
    
    // Update in transaction
    const db = await getDatabaseConnection();
    await db.transaction(async (trx) => {
      await updatePatientProfile(patientId, updates, trx);
      await logAuditEvent({
        userId: userContext.userId,
        action: 'UPDATE_PATIENT_PROFILE',
        patientId,
        changes: updates,
        timestamp: new Date()
      }, trx);
    });
    
    // Invalidate cache
    await invalidateCache(`patient:${patientId}`);
    
    // Notify connected clients
    await publishPatientUpdate(patientId, {
      type: 'PROFILE_UPDATED',
      changes: updates
    });
    
    return { status: 'updated' };
  }
};

// Medication management service
const MedicationService = {
  async createMedicationSchedule(medicationData, userContext) {
    // Validate medication data
    const validationResult = validateMedicationData(medicationData);
    if (!validationResult.isValid) {
      throw new Error(`Medication validation failed: ${validationResult.errors.join(', ')}`);
    }
    
    // Create schedule in database
    const scheduleId = await createMedicationSchedule({
      ...medicationData,
      createdBy: userContext.userId,
      createdAt: new Date()
    });
    
    // Send configuration to pillcase device
    await sendDeviceCommand(medicationData.deviceId, {
      type: 'UPDATE_SCHEDULE',
      schedule: medicationData.schedule
    });
    
    // Schedule reminder notifications
    await scheduleReminders(scheduleId, medicationData.schedule);
    
    return {
      scheduleId,
      status: 'created',
      deviceConfigured: true
    };
  },
  
  async getAdherenceAnalytics(patientId, timeframe, userContext) {
    // Verify access
    if (!await hasPatientAccess(userContext.userId, patientId)) {
      throw new Error('Access denied');
    }
    
    // Get adherence data from multiple sources
    const [deviceData, selfReports, missedDoses, patterns] = await Promise.all([
      getDeviceAdherenceData(patientId, timeframe),
      getSelfReportedAdherence(patientId, timeframe),
      getMissedDoseAnalysis(patientId, timeframe),
      getAdherencePatterns(patientId, timeframe)
    ]);
    
    // Calculate composite adherence score
    const compositeScore = calculateCompositeAdherenceScore({
      device: deviceData,
      selfReports,
      missedDoses,
      patterns
    });
    
    // Generate recommendations
    const recommendations = generateAdherenceRecommendations(compositeScore, patterns);
    
    return {
      timeframe,
      compositeScore,
      breakdown: {
        device: deviceData,
        selfReported: selfReports,
        missedDoses,
        patterns
      },
      recommendations,
      trends: calculateTrends(patterns)
    };
  }
};

// Real-time updates via WebSocket
class PatientDashboardWebSocket {
  constructor() {
    this.clients = new Map(); // patientId -> Set of client connections
  }
  
  async connectClient(patientId, websocket, userContext) {
    // Verify authentication
    if (!await this.verifyUserAccess(userContext, patientId)) {
      websocket.close(1008, 'Unauthorized');
      return;
    }
    
    // Add to client registry
    if (!this.clients.has(patientId)) {
      this.clients.set(patientId, new Set());
    }
    this.clients.get(patientId).add(websocket);
    
    // Setup event listeners
    websocket.on('close', () => {
      this.clients.get(patientId)?.delete(websocket);
    });
    
    // Send initial dashboard data
    await this.sendDashboardData(patientId, websocket);
  }
  
  async sendDashboardData(patientId, websocket) {
    try {
      const dashboardData = await PatientService.getPatient(patientId, null);
      
      websocket.send(JSON.stringify({
        type: 'DASHBOARD_UPDATE',
        data: dashboardData,
        timestamp: Date.now()
      }));
    } catch (error) {
      console.error('Failed to send dashboard data:', error);
    }
  }
  
  async notifyPatientUpdate(patientId, update) {
    const clients = this.clients.get(patientId);
    if (!clients) return;
    
    const message = JSON.stringify({
      type: 'REAL_TIME_UPDATE',
      update,
      timestamp: Date.now()
    });
    
    clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }
  
  // Subscribe to real-time events
  async subscribeToEvents() {
    // Subscribe to IoT device events
    await subscribeToIoTEvents('medical/devices/+/medication_intake', async (event) => {
      await this.notifyPatientUpdate(event.patientId, {
        source: 'DEVICE',
        type: 'MEDICATION_TAKEN',
        data: event
      });
    });
    
    // Subscribe to care team updates
    await subscribeToCareTeamEvents('care-team/updates', async (event) => {
      await this.notifyPatientUpdate(event.patientId, {
        source: 'CARE_TEAM',
        type: 'CARE_UPDATE',
        data: event
      });
    });
  }
}
```

## 3. Video Analytics & Security System Architecture

### Camera Management & Analytics Pipeline

```javascript
// Camera device management system
class CameraDeviceManager {
  constructor() {
    this.cameras = new Map();
    this.streamProcessors = new Map();
    this.analyticsPipeline = new AnalyticsPipeline();
  }
  
  async registerCamera(cameraConfig) {
    // Validate camera configuration
    const validationResult = await this.validateCameraConfig(cameraConfig);
    if (!validationResult.isValid) {
      throw new Error(`Invalid camera config: ${validationResult.errors.join(', ')}`);
    }
    
    // Create camera instance
    const camera = new CameraDevice(cameraConfig);
    
    // Initialize video stream
    await camera.initializeStream();
    
    // Setup analytics processing
    const streamProcessor = new StreamProcessor(camera);
    await streamProcessor.initialize();
    
    // Register in system
    this.cameras.set(cameraConfig.id, camera);
    this.streamProcessors.set(cameraConfig.id, streamProcessor);
    
    // Start analytics pipeline
    await this.analyticsPipeline.registerCamera(cameraConfig.id, streamProcessor);
    
    return {
      cameraId: cameraConfig.id,
      status: 'registered',
      streamActive: true
    };
  }
  
  async processVideoStream(cameraId) {
    const camera = this.cameras.get(cameraId);
    if (!camera) {
      throw new Error(`Camera ${cameraId} not found`);
    }
    
    const processor = this.streamProcessors.get(cameraId);
    
    // Setup frame extraction
    const frameExtractor = new FrameExtractor({
      fps: 5, // Extract 5 frames per second
      resolution: { width: 640, height: 480 },
      format: 'jpeg'
    });
    
    // Start processing pipeline
    await processor.startProcessing(async (frame) => {
      // Send frame to AI inference
      const analysisResults = await this.analyticsPipeline.analyzeFrame(cameraId, frame);
      
      // Process results
      await this.processAnalysisResults(cameraId, analysisResults);
      
      // Check for security events
      await this.checkSecurityEvents(cameraId, analysisResults);
    });
    
    return {
      status: 'processing',
      cameraId,
      streamUrl: camera.getStreamUrl(),
      analyticsActive: true
    };
  }
}

// Analytics pipeline for video processing
class AnalyticsPipeline {
  constructor() {
    this.models = {
      personDetection: new PersonDetectionModel(),
      objectDetection: new ObjectDetectionModel(),
      activityRecognition: new ActivityRecognitionModel(),
      anomalyDetection: new AnomalyDetectionModel()
    };
    this.eventHandlers = new Map();
  }
  
  async analyzeFrame(cameraId, frame) {
    const analysisResults = {};
    
    try {
      // Run multiple AI models in parallel
      const [personResults, objectResults, activityResults, anomalyResults] = await Promise.all([
        this.models.personDetection.detect(frame),
        this.models.objectDetection.detect(frame),
        this.models.activityRecognition.analyze(frame),
        this.models.anomalyDetection.detect(frame)
      ]);
      
      analysisResults.personDetection = personResults;
      analysisResults.objectDetection = objectResults;
      analysisResults.activityRecognition = activityResults;
      analysisResults.anomalyDetection = anomalyResults;
      
      // Combine results into meaningful events
      const events = this.generateEvents(analysisResults);
      
      return {
        cameraId,
        timestamp: Date.now(),
        results: analysisResults,
        events,
        confidence: this.calculateOverallConfidence(analysisResults)
      };
      
    } catch (error) {
      console.error('Frame analysis failed:', error);
      return {
        cameraId,
        timestamp: Date.now(),
        error: error.message,
        results: null
      };
    }
  }
  
  generateEvents(analysisResults) {
    const events = [];
    
    // Person detection events
    if (analysisResults.personDetection.confidence > 0.8) {
      events.push({
        type: 'PERSON_DETECTED',
        confidence: analysisResults.personDetection.confidence,
        boundingBox: analysisResults.personDetection.boundingBox,
        timestamp: Date.now()
      });
    }
    
    // Suspicious activity detection
    if (analysisResults.activityRecognition.activity === 'suspicious') {
      events.push({
        type: 'SUSPICIOUS_ACTIVITY',
        activity: analysisResults.activityRecognition.activity,
        confidence: analysisResults.activityRecognition.confidence,
        description: analysisResults.activityRecognition.description,
        timestamp: Date.now()
      });
    }
    
    // Anomaly detection
    if (analysisResults.anomalyDetection.isAnomaly) {
      events.push({
        type: 'ANOMALY_DETECTED',
        anomalyType: analysisResults.anomalyDetection.type,
        severity: analysisResults.anomalyDetection.severity,
        timestamp: Date.now()
      });
    }
    
    return events;
  }
  
  // Event processing and routing
  async processAnalysisResults(cameraId, analysisResults) {
    if (!analysisResults.events || analysisResults.events.length === 0) {
      return;
    }
    
    // Store analytics data
    await this.storeAnalyticsData(cameraId, analysisResults);
    
    // Route events based on severity
    for (const event of analysisResults.events) {
      switch (event.type) {
        case 'PERSON_DETECTED':
          await this.handlePersonDetection(cameraId, event);
          break;
        case 'SUSPICIOUS_ACTIVITY':
          await this.handleSuspiciousActivity(cameraId, event);
          break;
        case 'ANOMALY_DETECTED':
          await this.handleAnomalyDetection(cameraId, event);
          break;
      }
    }
  }
  
  async handlePersonDetection(cameraId, event) {
    // Check against authorized personnel database
    const isAuthorized = await this.checkAuthorization(cameraId, event.boundingBox);
    
    if (!isAuthorized) {
      // Trigger security alert
      await this.triggerSecurityAlert(cameraId, {
        type: 'UNAUTHORIZED_ACCESS',
        event,
        priority: 'MEDIUM'
      });
    }
    
    // Update occupancy tracking
    await this.updateOccupancyTracking(cameraId, event);
  }
  
  async handleSuspiciousActivity(cameraId, event) {
    // Determine response based on location and time
    const responseLevel = await this.calculateResponseLevel(cameraId, event);
    
    if (responseLevel >= 'MEDIUM') {
      await this.triggerSecurityAlert(cameraId, {
        type: 'SUSPICIOUS_ACTIVITY',
        event,
        priority: responseLevel,
        requiresImmediateResponse: responseLevel === 'HIGH'
      });
    }
  }
}

// Security event management
class SecurityEventManager {
  constructor() {
    this.alertChannels = {
      email: new EmailAlertService(),
      sms: new SMSAlertService(),
      push: new PushNotificationService(),
      webhooks: new WebhookAlertService()
    };
    this.escalationMatrix = new Map();
  }
  
  async triggerSecurityAlert(cameraId, alertData) {
    // Determine alert recipients based on camera location and severity
    const recipients = await this.determineRecipients(cameraId, alertData.priority);
    
    // Create alert message
    const alert = {
      cameraId,
      alertType: alertData.type,
      priority: alertData.priority,
      timestamp: Date.now(),
      message: this.generateAlertMessage(alertData),
      metadata: alertData.event,
      requiresResponse: alertData.requiresImmediateResponse || false
    };
    
    // Send alerts via multiple channels
    const deliveryPromises = recipients.map(recipient => 
      this.sendAlert(recipient, alert)
    );
    
    await Promise.allSettled(deliveryPromises);
    
    // Log security event
    await this.logSecurityEvent(alert);
    
    // Auto-escalate if not acknowledged within SLA
    if (alert.requiresResponse) {
      await this.scheduleEscalation(alert);
    }
  }
  
  async sendAlert(recipient, alert) {
    const channel = this.alertChannels[recipient.channel];
    if (!channel) {
      throw new Error(`Unknown alert channel: ${recipient.channel}`);
    }
    
    return await channel.send({
      to: recipient.address,
      subject: alert.subject || this.generateAlertSubject(alert),
      message: alert.message,
      priority: alert.priority,
      metadata: alert.metadata
    });
  }
}
```

## 4. Integration Architecture - Unified Platform

### Event-Driven Integration

```javascript
// Unified event bus for cross-system communication
class UnifiedEventBus {
  constructor() {
    this.eventStore = new Map();
    this.subscribers = new Map();
    this.eventRouter = new EventRouter();
  }
  
  // Publish events across all systems
  async publish(event) {
    // Store event for audit and replay
    await this.storeEvent(event);
    
    // Route to relevant subsystems
    const subscriptions = await this.getRelevantSubscriptions(event);
    
    const deliveryPromises = subscriptions.map(subscription => 
      this.deliverEvent(subscription, event)
    );
    
    await Promise.allSettled(deliveryPromises);
    
    return {
      eventId: event.id,
      deliveredTo: subscriptions.length,
      timestamp: Date.now()
    };
  }
  
  // Handle cross-system event processing
  async handleCrossSystemEvents() {
    // Medical IoT → Video Analytics integration
    await this.subscribeToEvents('medical/device/*/emergency', async (event) => {
      // Trigger camera focus on patient location
      await this.triggerCameraFocus(event.patientLocation);
      
      // Enable enhanced monitoring
      await this.activateEnhancedMonitoring(event.deviceId);
      
      // Notify care team with video context
      await this.notifyCareTeamWithVideo({
        patientId: event.patientId,
        emergencyType: event.type,
        location: event.patientLocation,
        timestamp: event.timestamp
      });
    });
    
    // Video Analytics → Medical IoT integration
    await this.subscribeToEvents('camera/*/unauthorized_access', async (event) => {
      // If unauthorized access near medical devices
      if (event.location.includes('medical_device_area')) {
        await this.secureMedicalDevices(event.area);
        
        // Trigger medication adherence verification
        await this.verifyMedicationAdherence(event.area);
      }
    });
    
    // Healthcare App → All Systems integration
    await this.subscribeToEvents('care_team/alert/*', async (event) => {
      // Update all device schedules
      await this.updateDeviceConfigurations(event.patientId);
      
      // Adjust video analytics sensitivity
      await this.adjustAnalyticsSensitivity(event.patientId);
      
      // Update dashboard notifications
      await this.updatePatientDashboard(event.patientId, event.alert);
    });
  }
  
  // Real-time synchronization across systems
  async setupRealTimeSync() {
    // Redis pub/sub for real-time updates
    const redis = new Redis(process.env.REDIS_URL);
    
    // Sync medication adherence events
    await redis.subscribe('medication_adherence', (message) => {
      const event = JSON.parse(message);
      this.publish({
        type: 'MEDICATION_ADHERENCE_UPDATE',
        source: 'MEDICAL_IOT',
        data: event,
        timestamp: Date.now()
      });
    });
    
    // Sync security events
    await redis.subscribe('security_events', (message) => {
      const event = JSON.parse(message);
      this.publish({
        type: 'SECURITY_EVENT',
        source: 'VIDEO_ANALYTICS',
        data: event,
        timestamp: Date.now()
      });
    });
    
    // Sync user actions
    await redis.subscribe('user_actions', (message) => {
      const event = JSON.parse(message);
      this.publish({
        type: 'USER_ACTION',
        source: 'HEALTHCARE_APP',
        data: event,
        timestamp: Date.now()
      });
    });
  }
}

// Integration workflow examples
class IntegrationWorkflows {
  
  // Emergency response workflow
  async handleMedicalEmergency(patientId, emergencyType) {
    console.log(`Handling medical emergency for patient ${patientId}: ${emergencyType}`);
    
    // 1. Activate all nearby cameras
    const nearbyCameras = await this.getNearbyCameras(patientId);
    await Promise.all(nearbyCameras.map(cameraId => 
      this.activateHighPriorityMonitoring(cameraId)
    ));
    
    // 2. Send device commands to enhance monitoring
    const patientDevices = await this.getPatientDevices(patientId);
    await Promise.all(patientDevices.map(deviceId =>
      this.sendDeviceCommand(deviceId, {
        type: 'EMERGENCY_MODE',
        duration: 3600 // 1 hour
      })
    ));
    
    // 3. Notify care team with full context
    await this.notifyCareTeam({
      patientId,
      emergencyType,
      location: await this.getPatientLocation(patientId),
      nearbyCameras,
      deviceStatus: await this.getDeviceStatus(patientDevices),
      timestamp: Date.now()
    });
    
    // 4. Update all dashboards
    await this.broadcastToPatientDashboards(patientId, {
      type: 'EMERGENCY_ACTIVATED',
      message: 'Emergency response activated',
      timestamp: Date.now()
    });
  }
  
  // Medication adherence verification workflow
  async verifyMedicationAdherence(patientId, verificationMethod = 'camera') {
    console.log(`Verifying medication adherence for patient ${patientId}`);
    
    // 1. Get expected medication schedule
    const schedule = await this.getCurrentMedicationSchedule(patientId);
    
    // 2. Check device data
    const deviceData = await this.getLatestDeviceData(patientId);
    
    // 3. If verification method is camera-based
    if (verificationMethod === 'camera') {
      const cameras = await this.getPatientLocationCameras(patientId);
      
      // Activate enhanced person detection
      await Promise.all(cameras.map(cameraId =>
        this.activateEnhancedPersonDetection(cameraId, {
          duration: 300, // 5 minutes
          focusAreas: await this.getMedicationIntakeAreas(patientId)
        })
      ));
      
      // Monitor for medication intake behavior
      await this.monitorMedicationIntake(patientId, cameras, 300);
    }
    
    // 4. Cross-reference with self-reports
    const selfReports = await this.getSelfReportedAdherence(patientId);
    const verificationResult = this.crossVerifyAdherence(deviceData, selfReports, schedule);
    
    // 5. Update adherence records
    await this.updateAdherenceRecords(patientId, verificationResult);
    
    // 6. Trigger alerts if discrepancies found
    if (verificationResult.discrepancies.length > 0) {
      await this.triggerAdherenceAlert(patientId, verificationResult);
    }
  }
  
  // Security incident response workflow
  async handleSecurityIncident(incidentData) {
    console.log(`Handling security incident: ${incidentData.type}`);
    
    // 1. Assess incident severity and scope
    const severity = await this.assessIncidentSeverity(incidentData);
    
    // 2. Activate affected cameras for enhanced monitoring
    const affectedCameras = await this.getAffectedCameras(incidentData.location);
    await Promise.all(affectedCameras.map(cameraId =>
      this.activateEnhancedMonitoring(cameraId, {
        duration: severity.duration,
        analytics: ['person_detection', 'activity_recognition', 'anomaly_detection']
      })
    ));
    
    // 3. Check if incident affects medical devices
    const affectedDevices = await this.getNearbyMedicalDevices(incidentData.location);
    if (affectedDevices.length > 0) {
      // Secure medical devices
      await Promise.all(affectedDevices.map(deviceId =>
        this.secureDevice(deviceId, {
          reason: 'Security incident',
          duration: severity.duration
        })
      ));
      
      // Alert medical staff
      await this.alertMedicalStaff({
        incident: incidentData,
        affectedDevices,
        securityAction: 'DEVICE_SECURED'
      });
    }
    
    // 4. Generate incident report
    await this.generateSecurityIncidentReport(incidentData);
    
    // 5. Update system-wide security status
    await this.updateSecurityStatus(incidentData.location, 'ENHANCED_ALERT');
  }
}
```

## 5. System Scalability & Performance

### Multi-Tenant Architecture

```javascript
// Multi-tenant data isolation
class MultiTenantManager {
  constructor() {
    this.tenantConfigs = new Map();
    this.dataPartitioners = new Map();
  }
  
  async setupTenant(tenantId, config) {
    // Store tenant configuration
    this.tenantConfigs.set(tenantId, {
      id: tenantId,
      name: config.name,
      region: config.region,
      compliance: config.compliance, // HIPAA, GDPR, etc.
      features: config.features,
      limits: config.limits,
      createdAt: new Date()
    });
    
    // Setup data partitioning
    await this.setupDataPartitioning(tenantId, config.dataStrategy);
    
    // Configure security policies
    await this.setupTenantSecurity(tenantId, config.security);
    
    // Initialize tenant-specific resources
    await this.initializeTenantResources(tenantId, config);
  }
  
  // Data partitioning strategies
  async setupDataPartitioning(tenantId, strategy) {
    switch (strategy.type) {
      case 'DATABASE_PER_TENANT':
        await this.createTenantDatabase(tenantId, strategy.config);
        break;
      case 'SCHEMA_PER_TENANT':
        await this.createTenantSchema(tenantId, strategy.config);
        break;
      case 'ROW_LEVEL_SECURITY':
        await this.setupRowLevelSecurity(tenantId, strategy.config);
        break;
      case 'TIME_BASED_PARTITIONING':
        await this.setupTimeBasedPartitioning(tenantId, strategy.config);
        break;
    }
  }
  
  // Tenant-specific API routing
  createTenantAwareAPI(tenantId) {
    return {
      // Prefix all operations with tenant context
      patients: {
        list: () => this.getTenantPatients(tenantId),
        get: (id) => this.getTenantPatient(tenantId, id),
        update: (id, data) => this.updateTenantPatient(tenantId, id, data)
      },
      devices: {
        list: () => this.getTenantDevices(tenantId),
        register: (config) => this.registerTenantDevice(tenantId, config),
        commands: (deviceId, command) => this.sendTenantCommand(tenantId, deviceId, command)
      },
      analytics: {
        adherence: (params) => this.getTenantAdherenceAnalytics(tenantId, params),
        security: (params) => this.getTenantSecurityAnalytics(tenantId, params)
      }
    };
  }
}

// Auto-scaling configuration
class AutoScalingManager {
  constructor() {
    this.scalingPolicies = new Map();
    this.metrics = new MetricsCollector();
  }
  
  // Medical IoT scaling
  setupIoTScaling() {
    const scalingPolicy = {
      service: 'iot-processing',
      metrics: [
        { name: 'MessagesPerSecond', threshold: 1000, action: 'scale_up' },
        { name: 'MessagesPerSecond', threshold: 100, action: 'scale_down' },
        { name: 'DeviceConnectionCount', threshold: 10000, action: 'scale_up' },
        { name: 'AverageLatency', threshold: 100, action: 'scale_up' }
      ],
      cooldown: 300, // 5 minutes
      minInstances: 2,
      maxInstances: 50
    };
    
    this.scalingPolicies.set('iot-processing', scalingPolicy);
  }
  
  // Video analytics scaling
  setupVideoAnalyticsScaling() {
    const scalingPolicy = {
      service: 'video-analytics',
      metrics: [
        { name: 'ActiveStreams', threshold: 100, action: 'scale_up' },
        { name: 'GPUUtilization', threshold: 80, action: 'scale_up' },
        { name: 'FrameProcessingTime', threshold: 100, action: 'scale_up' },
        { name: 'QueueDepth', threshold: 1000, action: 'scale_up' }
      ],
      cooldown: 180,
      minInstances: 1,
      maxInstances: 20,
      gpuRequired: true
    };
    
    this.scalingPolicies.set('video-analytics', scalingPolicy);
  }
  
  // Execute scaling based on metrics
  async evaluateScaling() {
    const currentMetrics = await this.metrics.getCurrentMetrics();
    
    for (const [service, policy] of this.scalingPolicies) {
      const serviceMetrics = currentMetrics[service];
      
      for (const metric of policy.metrics) {
        const currentValue = serviceMetrics[metric.name];
        
        if (this.shouldScale(currentValue, metric, policy)) {
          await this.executeScaling(service, metric.action, policy);
          break; // Only one scaling action per evaluation cycle
        }
      }
    }
  }
}
```

This comprehensive architecture document demonstrates your deep understanding of building and integrating complex IoT, web, and video analytics systems, showing expertise in:

- **Medical IoT device management** and real-time data processing
- **Healthcare web application** architecture with security and compliance
- **Video analytics pipeline** with AI/ML integration
- **Cross-system integration** and event-driven architecture
- **Scalability and multi-tenancy** for enterprise deployments
- **Security and compliance** considerations for healthcare data
- **Performance optimization** and auto-scaling strategies

This integrated approach shows how all three systems work together to create a comprehensive healthcare monitoring and security platform.