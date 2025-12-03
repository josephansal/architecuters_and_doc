# Video Analytics Interview Answers - Comprehensive Guide

## 1. Junior-Level Interview Questions (Basics Understanding)

### Video & Streaming Basics

#### What is WebRTC and why is it used for real-time video streaming?
WebRTC (Web Real-Time Communication) is a protocol for peer-to-peer communication that enables real-time audio, video, and data sharing between browsers and devices.

**Key Features:**
- **Low Latency:** Sub-second delay for real-time communication
- **Peer-to-Peer:** Direct connection between devices when possible
- **Cross-Platform:** Works on web, mobile, and desktop
- **Encrypted:** Built-in DTLS/SRTP encryption
- **Adaptive:** Automatically adjusts to network conditions

```javascript
// Basic WebRTC implementation for camera streaming
class VideoStreamer {
  constructor() {
    this.peerConnection = null;
    this.localStream = null;
    this.remoteStream = null;
  }
  
  async initializeCamera() {
    try {
      // Get camera access
      this.localStream = await navigator.mediaDevices.getUserMedia({
        video: {
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: 30 }
        },
        audio: false // For video analytics, audio might not be needed
      });
      
      return this.localStream;
    } catch (error) {
      console.error('Camera access failed:', error);
      throw new Error('Cannot access camera');
    }
  }
  
  async createPeerConnection() {
    const configuration = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'turn:turn-server.example.com', username: 'user', credential: 'pass' }
      ]
    };
    
    this.peerConnection = new RTCPeerConnection(configuration);
    
    // Handle remote stream
    this.remoteStream = new MediaStream();
    this.peerConnection.ontrack = (event) => {
      this.remoteStream.addTrack(event.track);
    };
    
    // Handle ICE candidates
    this.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendICECandidate(event.candidate);
      }
    };
    
    return this.peerConnection;
  }
  
  async startStreaming() {
    // Create peer connection
    await this.createPeerConnection();
    
    // Add local stream to peer connection
    this.localStream.getTracks().forEach(track => {
      this.peerConnection.addTrack(track, this.localStream);
    });
    
    // Create offer
    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);
    
    // Send offer to remote peer
    await this.sendOffer(offer);
  }
  
  async handleAnswer(answer) {
    await this.peerConnection.setRemoteDescription(answer);
  }
  
  async handleICECandidate(candidate) {
    await this.peerConnection.addIceCandidate(candidate);
  }
  
  stopStreaming() {
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop());
    }
    if (this.peerConnection) {
      this.peerConnection.close();
    }
  }
}

// Usage for real-time video analytics
const videoStreamer = new VideoStreamer();
await videoStreamer.initializeCamera();
await videoStreamer.startStreaming();
```

#### What is the difference between RTSP, WebRTC, and HLS?
| Protocol | Use Case | Latency | Directionality | Best For |
|----------|----------|---------|----------------|----------|
| **RTSP** | Security cameras | Low (2-5s) | Unidirectional | Traditional CCTV systems |
| **WebRTC** | Real-time communication | Ultra-low (<1s) | Bidirectional | Interactive applications |
| **HLS** | Video streaming | High (10-30s) | Unidirectional | Video-on-demand, broadcast |

**RTSP Implementation:**
```javascript
// RTSP stream handling for IP cameras
class RTSPStreamHandler {
  constructor(cameraConfig) {
    this.cameraUrl = cameraConfig.rtspUrl;
    this.username = cameraConfig.username;
    this.password = cameraConfig.password;
    this.isConnected = false;
  }
  
  async connect() {
    try {
      // RTSP URL format: rtsp://username:password@camera-ip:port/stream
      const rtspUrl = `rtsp://${this.username}:${this.password}@${this.cameraUrl}`;
      
      // Use FFmpeg to convert RTSP to web-compatible format
      const ffmpegCommand = [
        '-i', rtspUrl,
        '-c:v', 'libx264',        // Video codec
        '-c:a', 'aac',            // Audio codec
        '-preset', 'fast',        // Encoding preset
        '-f', 'flv',              // Output format for WebSocket
        'rtmp://localhost/live/stream'
      ].join(' ');
      
      // Start FFmpeg process
      const ffmpeg = spawn('ffmpeg', ffmpegCommand.split(' '));
      
      ffmpeg.stderr.on('data', (data) => {
        console.log(`FFmpeg: ${data}`);
      });
      
      ffmpeg.on('close', (code) => {
        console.log(`FFmpeg process exited with code ${code}`);
        this.isConnected = false;
      });
      
      this.isConnected = true;
      return true;
    } catch (error) {
      console.error('RTSP connection failed:', error);
      return false;
    }
  }
  
  disconnect() {
    // Kill FFmpeg process
    if (this.ffmpegProcess) {
      this.ffmpegProcess.kill('SIGTERM');
    }
    this.isConnected = false;
  }
}
```

**HLS Implementation:**
```javascript
// HLS streaming setup for video-on-demand
class HLSStreamManager {
  constructor() {
    this.manifestUrl = null;
    this.segments = [];
  }
  
  async setupHLSStream(videoFile, outputDir) {
    // Use FFmpeg to create HLS streams
    const hlsCommand = [
      '-i', videoFile,
      '-codec:v', 'libx264',
      '-codec:a', 'aac',
      '-start_number', '0',
      '-hls_time', '6',
      '-hls_list_size', '0',
      '-f', 'hls',
      '-hls_segment_filename', `${outputDir}/segment%03d.ts`,
      `${outputDir}/playlist.m3u8`
    ].join(' ');
    
    return new Promise((resolve, reject) => {
      const ffmpeg = spawn('ffmpeg', hlsCommand.split(' '));
      
      ffmpeg.on('close', (code) => {
        if (code === 0) {
          resolve({
            manifestUrl: `${outputDir}/playlist.m3u8`,
            segments: this.segments
          });
        } else {
          reject(new Error(`FFmpeg exited with code ${code}`));
        }
      });
      
      ffmpeg.stderr.on('data', (data) => {
        console.log(`HLS FFmpeg: ${data}`);
      });
    });
  }
  
  generateAdaptiveBitrateStreams(inputVideo, outputDir) {
    const variants = [
      { name: '1080p', resolution: '1920x1080', bitrate: '5000k' },
      { name: '720p', resolution: '1280x720', bitrate: '3000k' },
      { name: '480p', resolution: '854x480', bitrate: '1500k' },
      { name: '360p', resolution: '640x360', bitrate: '800k' }
    ];
    
    variants.forEach(variant => {
      const variantDir = `${outputDir}/${variant.name}`;
      fs.mkdirSync(variantDir, { recursive: true });
      
      const command = [
        '-i', inputVideo,
        '-s', variant.resolution,
        '-b:v', variant.bitrate,
        '-c:v', 'libx264',
        '-c:a', 'aac',
        '-start_number', '0',
        '-hls_time', '6',
        '-hls_list_size', '0',
        '-f', 'hls',
        '-hls_segment_filename', `${variantDir}/segment%03d.ts`,
        `${variantDir}/playlist.m3u8`
      ].join(' ');
      
      spawn('ffmpeg', command.split(' '));
    });
  }
}
```

#### What is a video frame, and what is FPS?
**Frame:** A single image in a video sequence
**FPS (Frames Per Second):** Number of frames displayed per second

```javascript
// Frame extraction and processing
class FrameProcessor {
  constructor(videoElement) {
    this.video = videoElement;
    this.canvas = document.createElement('canvas');
    this.ctx = this.canvas.getContext('2d');
  }
  
  // Extract frame from video
  extractFrame(timeInSeconds = null) {
    if (timeInSeconds !== null) {
      this.video.currentTime = timeInSeconds;
    }
    
    this.canvas.width = this.video.videoWidth;
    this.canvas.height = this.video.videoHeight;
    
    // Draw current frame to canvas
    this.ctx.drawImage(this.video, 0, 0);
    
    // Get image data
    const imageData = this.ctx.getImageData(0, 0, this.canvas.width, this.canvas.height);
    
    return imageData;
  }
  
  // Calculate FPS from video metadata
  getVideoFPS() {
    // Most videos have metadata about frame rate
    const videoTracks = this.video.videoTracks;
    if (videoTracks && videoTracks.length > 0) {
      const track = videoTracks[0];
      if (track.frameRate) {
        return track.frameRate;
      }
    }
    
    // Fallback: Estimate from duration and frame count
    return 30; // Default assumption
  }
  
  // Frame rate conversion
  convertFrameRate(inputVideo, outputFPS, outputPath) {
    const command = [
      '-i', inputVideo,
      '-r', outputFPS.toString(),
      '-c:v', 'libx264',
      '-crf', '23',
      '-preset', 'medium',
      outputPath
    ].join(' ');
    
    return new Promise((resolve, reject) => {
      const ffmpeg = spawn('ffmpeg', command.split(' '));
      
      ffmpeg.on('close', (code) => {
        if (code === 0) {
          resolve(outputPath);
        } else {
          reject(new Error(`Frame rate conversion failed with code ${code}`));
        }
      });
    });
  }
}

// Usage for video analytics
const frameProcessor = new FrameProcessor(videoElement);

// Extract frames at specific intervals for AI processing
async function extractFramesForAnalytics(videoPath, intervalSeconds = 1) {
  const video = document.createElement('video');
  video.src = videoPath;
  
  await new Promise(resolve => {
    video.addEventListener('loadedmetadata', resolve);
  });
  
  const totalDuration = video.duration;
  const frames = [];
  
  for (let time = 0; time < totalDuration; time += intervalSeconds) {
    const frame = frameProcessor.extractFrame(time);
    frames.push({
      time: time,
      imageData: frame,
      width: frame.width,
      height: frame.height
    });
    
    // Allow UI to remain responsive
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  
  return frames;
}
```

### MQTT Messaging

#### What is MQTT?
MQTT (Message Queuing Telemetry Transport) is a lightweight publish-subscribe messaging protocol for IoT devices.

```javascript
// MQTT client for camera events
const mqtt = require('mqtt');
const client = mqtt.connect('mqtt://broker.example.com', {
  clientId: 'camera-' + Math.random().toString(16),
  clean: true,
  connectTimeout: 4000,
  reconnectPeriod: 1000,
});

client.on('connect', () => {
  console.log('Connected to MQTT broker');
  
  // Subscribe to camera events
  client.subscribe('cameras/+/events', (err) => {
    if (!err) {
      console.log('Subscribed to camera events');
    }
  });
});

// Handle incoming camera events
client.on('message', (topic, message) => {
  try {
    const event = JSON.parse(message.toString());
    console.log(`Received event from ${topic}:`, event);
    
    switch (event.type) {
      case 'motion_detected':
        handleMotionDetection(event);
        break;
      case 'object_detected':
        handleObjectDetection(event);
        break;
      case 'camera_offline':
        handleCameraOffline(event);
        break;
      default:
        console.log('Unknown event type:', event.type);
    }
  } catch (error) {
    console.error('Failed to parse MQTT message:', error);
  }
});

// Publish camera status
function publishCameraStatus(cameraId, status) {
  const topic = `cameras/${cameraId}/status`;
  const message = JSON.stringify({
    cameraId: cameraId,
    status: status,
    timestamp: new Date().toISOString(),
    batteryLevel: getBatteryLevel(cameraId),
    connectivity: getConnectivityStatus(cameraId)
  });
  
  client.publish(topic, message, { qos: 1 }, (err) => {
    if (err) {
      console.error('Failed to publish status:', err);
    }
  });
}
```

#### What is a topic in MQTT?
Topics are UTF-8 strings that categorize messages using a hierarchical structure.

```javascript
// Topic hierarchy for video analytics system
const topicStructure = {
  cameras: 'cameras/{camera_id}/events',
  streams: 'streams/{stream_id}/status',
  analytics: 'analytics/{camera_id}/results',
  alerts: 'alerts/{priority}/{camera_id}',
  system: 'system/{component}/{action}'
};

// Example topic usage
const topics = {
  // Camera-specific events
  motionDetection: 'cameras/camera-001/events',
  objectDetection: 'cameras/camera-002/analytics',
  
  // Stream status updates
  streamStatus: 'streams/live-stream-001/status',
  
  // Analytics results
  analyticsResults: 'analytics/camera-001/results',
  
  // Alert system
  criticalAlert: 'alerts/critical/camera-001',
  warningAlert: 'alerts/warning/camera-001',
  
  // System management
  cameraConfig: 'system/cameras/config',
  serviceHealth: 'system/health/microservices'
};

// Subscribe to multiple topics with wildcards
function setupSubscriptions(client) {
  // All camera events
  client.subscribe('cameras/+/events');
  
  // All analytics results
  client.subscribe('analytics/+/results');
  
  // All critical alerts
  client.subscribe('alerts/critical/+');
  
  // All system health updates
  client.subscribe('system/health/+');
}

// Topic-based routing
function routeMessage(topic, message) {
  const topicParts = topic.split('/');
  
  switch (topicParts[0]) {
    case 'cameras':
      handleCameraMessage(topicParts[1], topicParts[3], message);
      break;
    case 'analytics':
      handleAnalyticsMessage(topicParts[1], message);
      break;
    case 'alerts':
      handleAlertMessage(topicParts[1], topicParts[2], message);
      break;
    case 'system':
      handleSystemMessage(topicParts[1], topicParts[2], message);
      break;
    default:
      console.log('Unknown topic:', topic);
  }
}
```

#### How does QoS work in MQTT?
QoS (Quality of Service) levels define message delivery guarantees.

```javascript
// QoS levels and their meanings
const qosLevels = {
  0: 'At most once (fire and forget)',
  1: 'At least once (acknowledged delivery)',
  2: 'Exactly once (assured delivery)'
};

// QoS implementation for video analytics
class VideoMQTTClient {
  constructor() {
    this.client = mqtt.connect('mqtt://broker.example.com');
    this.setupEventHandlers();
  }
  
  // QoS 0: Best effort for real-time telemetry
  async publishTelemetry(cameraId, telemetryData) {
    const topic = `cameras/${cameraId}/telemetry`;
    
    // No acknowledgment needed, fire and forget
    this.client.publish(
      topic,
      JSON.stringify(telemetryData),
      { qos: 0 }, // QoS 0
      (err) => {
        if (err) {
          console.error('Telemetry publish failed:', err);
        }
      }
    );
  }
  
  // QoS 1: Ensure critical events are delivered
  async publishCriticalEvent(cameraId, eventData) {
    const topic = `cameras/${cameraId}/critical-events`;
    
    // Ensure delivery with acknowledgment
    return new Promise((resolve, reject) => {
      this.client.publish(
        topic,
        JSON.stringify(eventData),
        { qos: 1 }, // QoS 1
        (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        }
      );
    });
  }
  
  // QoS 2: Exactly once for configuration updates
  async publishConfiguration(cameraId, config) {
    const topic = `cameras/${cameraId}/configuration`;
    
    // Most reliable delivery for critical configurations
    return new Promise((resolve, reject) => {
      this.client.publish(
        topic,
        JSON.stringify(config),
        { qos: 2 }, // QoS 2
        (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        }
      );
    });
  }
  
  setupEventHandlers() {
    // Handle QoS acknowledgments
    this.client.on('ack', (packet) => {
      console.log(`Acknowledged ${packet.qos} QoS for topic: ${packet.topic}`);
    });
    
    // Handle message retries for QoS 1 and 2
    this.client.on('reconnect', () => {
      console.log('Reconnecting to MQTT broker...');
      
      // Re-subscribe to topics after reconnection
      this.resubscribeTopics();
    });
  }
  
  async resubscribeTopics() {
    const subscriptions = [
      { topic: 'cameras/+/events', qos: 1 },
      { topic: 'analytics/+/results', qos: 1 },
      { topic: 'alerts/+/+', qos: 2 }
    ];
    
    subscriptions.forEach(sub => {
      this.client.subscribe(sub.topic, { qos: sub.qos });
    });
  }
}

// Usage
const videoMQTT = new VideoMQTTClient();

// Publish different types of messages with appropriate QoS
async function publishMessages() {
  // Real-time telemetry - QoS 0
  await videoMQTT.publishTelemetry('camera-001', {
    temperature: 45,
    humidity: 60,
    timestamp: Date.now()
  });
  
  // Critical motion detection - QoS 1
  await videoMQTT.publishCriticalEvent('camera-001', {
    type: 'motion_detected',
    confidence: 0.95,
    location: 'entrance',
    timestamp: Date.now()
  });
  
  // Configuration update - QoS 2
  await videoMQTT.publishConfiguration('camera-001', {
    recordingEnabled: true,
    motionSensitivity: 0.8,
    nightVisionEnabled: true
  });
}
```

## 2. Senior-Level Interview Questions (Deep Technical Understanding)

### Video & AI Pipeline

#### How would you stream a live camera feed to a web application?
```javascript
// Complete live streaming pipeline
class LiveVideoStreamer {
  constructor(cameraConfig) {
    this.cameraConfig = cameraConfig;
    this.webrtcConnection = null;
    this.mediaRecorder = null;
    this.chunks = [];
    this.websocket = null;
  }
  
  // Setup WebRTC peer connection
  async setupWebRTCStream() {
    const peerConnection = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'turn:turn.example.com', username: 'user', credential: 'pass' }
      ]
    });
    
    // Get camera stream
    const stream = await navigator.mediaDevices.getUserMedia({
      video: {
        width: { ideal: 1920 },
        height: { ideal: 1080 },
        frameRate: { ideal: 30 }
      },
      audio: false
    });
    
    // Add tracks to peer connection
    stream.getTracks().forEach(track => {
      peerConnection.addTrack(track, stream);
    });
    
    // Handle ICE candidates
    peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendSignalingMessage({
          type: 'ice-candidate',
          candidate: event.candidate
        });
      }
    };
    
    // Handle remote stream
    peerConnection.ontrack = (event) => {
      const [remoteStream] = event.streams;
      this.displayRemoteStream(remoteStream);
    };
    
    this.webrtcConnection = peerConnection;
    return peerConnection;
  }
  
  // Create WebSocket signaling server
  setupSignalingServer() {
    this.websocket = new WebSocket('wss://signaling-server.example.com');
    
    this.websocket.onopen = () => {
      console.log('Connected to signaling server');
    };
    
    this.websocket.onmessage = async (event) => {
      const message = JSON.parse(event.data);
      await this.handleSignalingMessage(message);
    };
    
    this.websocket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }
  
  async handleSignalingMessage(message) {
    switch (message.type) {
      case 'offer':
        await this.webrtcConnection.setRemoteDescription(message.offer);
        const answer = await this.webrtcConnection.createAnswer();
        await this.webrtcConnection.setLocalDescription(answer);
        this.sendSignalingMessage({ type: 'answer', answer });
        break;
        
      case 'answer':
        await this.webrtcConnection.setRemoteDescription(message.answer);
        break;
        
      case 'ice-candidate':
        try {
          await this.webrtcConnection.addIceCandidate(message.candidate);
        } catch (error) {
          console.error('Error adding ICE candidate:', error);
        }
        break;
    }
  }
  
  // Setup video recording and streaming
  setupVideoRecording(stream) {
    this.mediaRecorder = new MediaRecorder(stream, {
      mimeType: 'video/webm; codecs=vp8',
      videoBitsPerSecond: 2000000 // 2 Mbps
    });
    
    this.mediaRecorder.ondataavailable = (event) => {
      if (event.data.size > 0) {
        this.chunks.push(event.data);
        this.processVideoChunk(event.data);
      }
    };
    
    this.mediaRecorder.onstop = () => {
      const blob = new Blob(this.chunks, { type: 'video/webm' });
      this.saveVideoSegment(blob);
      this.chunks = [];
    };
    
    // Record in 10-second segments
    this.mediaRecorder.start(10000);
  }
  
  // Process video for analytics
  processVideoChunk(chunk) {
    const formData = new FormData();
    formData.append('video', chunk, 'segment.webm');
    formData.append('timestamp', Date.now().toString());
    formData.append('cameraId', this.cameraConfig.id);
    
    // Send to AI processing service
    fetch('/api/analytics/process', {
      method: 'POST',
      body: formData
    })
    .then(response => response.json())
    .then(results => {
      this.handleAnalyticsResults(results);
    })
    .catch(error => {
      console.error('Analytics processing failed:', error);
    });
  }
  
  handleAnalyticsResults(results) {
    // Publish results via WebSocket to connected clients
    if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
      this.websocket.send(JSON.stringify({
        type: 'analytics-results',
        cameraId: this.cameraConfig.id,
        results: results,
        timestamp: Date.now()
      }));
    }
    
    // Store results in database
    this.saveAnalyticsResults(results);
    
    // Trigger alerts if necessary
    this.checkForAlerts(results);
  }
  
  // Start the complete streaming pipeline
  async startStreaming() {
    await this.setupWebRTCStream();
    this.setupSignalingServer();
    this.setupVideoRecording(this.webrtcConnection.getLocalStream());
    
    console.log('Live streaming started');
  }
  
  stopStreaming() {
    if (this.mediaRecorder && this.mediaRecorder.state === 'recording') {
      this.mediaRecorder.stop();
    }
    
    if (this.webrtcConnection) {
      this.webrtcConnection.close();
    }
    
    if (this.websocket) {
      this.websocket.close();
    }
  }
}

// Client-side video display
class VideoDisplay {
  constructor(videoElement) {
    this.video = videoElement;
  }
  
  displayRemoteStream(stream) {
    this.video.srcObject = stream;
    this.video.play().catch(error => {
      console.error('Video play failed:', error);
    });
  }
  
  setupAnalyticsOverlay(results) {
    const canvas = document.createElement('canvas');
    canvas.width = this.video.videoWidth;
    canvas.height = this.video.videoHeight;
    canvas.style.position = 'absolute';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.pointerEvents = 'none';
    
    const ctx = canvas.getContext('2d');
    
    // Draw detection boxes and labels
    results.detections.forEach(detection => {
      const { x, y, width, height, class: className, confidence } = detection;
      
      // Draw bounding box
      ctx.strokeStyle = this.getColorForClass(className);
      ctx.lineWidth = 2;
      ctx.strokeRect(x, y, width, height);
      
      // Draw label
      ctx.fillStyle = this.getColorForClass(className);
      ctx.font = '14px Arial';
      ctx.fillText(`${className} (${(confidence * 100).toFixed(1)}%)`, x, y - 5);
    });
    
    this.video.parentElement.appendChild(canvas);
  }
  
  getColorForClass(className) {
    const colors = {
      'person': '#00ff00',
      'vehicle': '#ff0000',
      'animal': '#0000ff',
      'unknown': '#ffff00'
    };
    return colors[className] || '#ffffff';
  }
}
```

#### How do you extract frames for AI inference without interrupting the stream?
```javascript
// Frame extraction without stream interruption
class FrameExtractor {
  constructor(stream, options = {}) {
    this.stream = stream;
    this.options = {
      fps: options.fps || 5, // Extract 5 frames per second
      quality: options.quality || 0.8,
      format: options.format || 'jpeg',
      ...options
    };
    
    this.canvas = document.createElement('canvas');
    this.ctx = this.canvas.getContext('2d', { willReadFrequently: true });
    this.video = document.createElement('video');
    this.frameInterval = 1000 / this.options.fps;
    this.lastExtraction = 0;
    this.isExtracting = false;
  }
  
  async initialize() {
    this.video.srcObject = this.stream;
    await new Promise(resolve => {
      this.video.addEventListener('loadedmetadata', resolve);
    });
    
    this.canvas.width = this.video.videoWidth;
    this.canvas.height = this.video.videoHeight;
  }
  
  // Start continuous frame extraction
  startExtraction() {
    this.isExtracting = true;
    this.extractFrameLoop();
  }
  
  stopExtraction() {
    this.isExtracting = false;
  }
  
  extractFrameLoop() {
    if (!this.isExtracting) return;
    
    const now = performance.now();
    
    if (now - this.lastExtraction >= this.frameInterval) {
      this.extractSingleFrame();
      this.lastExtraction = now;
    }
    
    requestAnimationFrame(() => this.extractFrameLoop());
  }
  
  extractSingleFrame() {
    try {
      // Draw current video frame to canvas
      this.ctx.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
      
      // Extract frame data without blocking the main thread
      const frameData = this.canvas.toDataURL(
        `image/${this.options.format}`, 
        this.options.quality
      );
      
      // Process frame asynchronously
      this.processFrame(frameData);
      
    } catch (error) {
      console.error('Frame extraction error:', error);
    }
  }
  
  async processFrame(frameData) {
    // Convert to blob for smaller size
    const blob = await this.dataURLToBlob(frameData);
    
    // Create analysis request
    const formData = new FormData();
    formData.append('frame', blob, 'frame.jpg');
    formData.append('timestamp', Date.now().toString());
    formData.append('cameraId', this.stream.id || 'unknown');
    
    // Send to AI inference service
    try {
      const response = await fetch('/api/inference/analyze', {
        method: 'POST',
        body: formData
      });
      
      const results = await response.json();
      
      // Trigger callback with results
      if (this.options.onFrameProcessed) {
        this.options.onFrameProcessed(results);
      }
      
    } catch (error) {
      console.error('Frame processing failed:', error);
    }
  }
  
  dataURLToBlob(dataURL) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        this.canvas.width = img.width;
        this.canvas.height = img.height;
        this.ctx.drawImage(img, 0, 0);
        
        this.canvas.toBlob(resolve, `image/${this.options.format}`, this.options.quality);
      };
      img.src = dataURL;
    });
  }
  
  // Extract frame at specific time
  extractFrameAtTime(timeInSeconds) {
    return new Promise((resolve, reject) => {
      this.video.currentTime = timeInSeconds;
      
      this.video.onseeked = () => {
        try {
          this.ctx.drawImage(this.video, 0, 0);
          const frameData = this.canvas.toDataURL(`image/${this.options.format}`);
          resolve(frameData);
        } catch (error) {
          reject(error);
        }
      };
      
      this.video.onerror = () => {
        reject(new Error('Failed to seek video'));
      };
    });
  }
}

// Usage with WebRTC stream
async function setupAIFrameExtraction(stream) {
  const extractor = new FrameExtractor(stream, {
    fps: 5,
    quality: 0.7,
    format: 'jpeg',
    onFrameProcessed: (results) => {
      // Handle AI results
      handleAIResults(results);
    }
  });
  
  await extractor.initialize();
  extractor.startExtraction();
  
  return extractor;
}

// Batch frame extraction for training data
class BatchFrameExtractor {
  async extractFramesForTraining(videoFile, outputDir, options = {}) {
    const {
      fps = 1,
      maxFrames = 1000,
      format = 'jpg',
      classes = []
    } = options;
    
    return new Promise((resolve, reject) => {
      const video = document.createElement('video');
      video.src = URL.createObjectURL(videoFile);
      video.crossOrigin = 'anonymous';
      
      video.onloadedmetadata = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        
        const frames = [];
        const frameInterval = 1000 / fps;
        let currentTime = 0;
        
        const extractNextFrame = () => {
          if (frames.length >= maxFrames || currentTime >= video.duration) {
            resolve(frames);
            return;
          }
          
          video.currentTime = currentTime;
          
          video.onseeked = () => {
            ctx.drawImage(video, 0, 0);
            
            canvas.toBlob((blob) => {
              frames.push({
                blob,
                timestamp: currentTime,
                filename: `frame_${frames.length.toString().padStart(6, '0')}.${format}`
              });
              
              currentTime += frameInterval / 1000;
              setTimeout(extractNextFrame, 0);
            }, `image/${format}`, 0.8);
          };
        };
        
        extractNextFrame();
      };
      
      video.onerror = () => {
        reject(new Error('Failed to load video'));
      };
    });
  }
}
```

This comprehensive guide covers video analytics systems from junior to architect level, demonstrating deep technical knowledge of video streaming protocols, AI pipeline integration, real-time processing, and scalable architecture patterns essential for senior technical positions in video analytics and computer vision domains.