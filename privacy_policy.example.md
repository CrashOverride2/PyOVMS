<!--
  TEMPLATE — NOT A POLICY.

  PyOVMS does not ship a privacy policy, because a privacy policy describes what *you*
  do with other people's data on *your* server. Copy this file to `privacy_policy.md`
  in the project root and adapt it; that filename is gitignored so your version never
  ends up in a fork.

  Until you do, `/privacy` returns 404 and the footer link is hidden.

  Replace every {{ PLACEHOLDER }} below, and check each claim against how you actually
  run the instance — the retention periods, the transport security and the third-party
  services listed here describe PyOVMS's defaults, not necessarily your deployment. If
  you serve users in the EU, this text is a starting point for a GDPR Art. 13/14 notice,
  not legal advice and not a substitute for reviewing it yourself.
-->

# Privacy Policy for {{ YOUR INSTANCE HOSTNAME }}

**Last Updated:** {{ DATE }}

This Privacy Policy describes how your personal and vehicle information is collected, used, and handled when you use this instance of the PyOVMS (Python Open Vehicle Monitoring System) server. The operator of this server, listed at the bottom of this policy, is responsible for the data processing described herein.

## 1. Information We Collect

To provide our service, we collect the following types of information:

*   **Account Information:** When you register, we collect your username, email address, and a securely hashed password. If you enable Two-Factor Authentication (2FA), an encrypted secret key is stored for your account. Optional information includes your full name, preferred timezone, and language.

*   **Vehicle Information:** To connect your vehicle, we store its unique ID, a display name (optional), and encrypted server/module passwords for authentication. We also store your configuration settings for notifications and connectivity.

*   **Vehicle Operational Data:** When your vehicle is connected, it sends data to the server. This includes, but is not limited to:
    *   **Location:** Real-time GPS coordinates, altitude, speed, and direction.
    *   **Status:** State of Charge (SOC), charging status, battery voltage, estimated range, and tire pressures (TPMS).
    *   **Diagnostics:** Vehicle temperatures (battery, motor), 12V system voltage, door/lock status, module firmware version, and vehicle crash logs.

*   **Trip Tracking Data (Opt-In):** If you explicitly enable the "Trip Tracking" feature for a vehicle, we collect and store historical journey data. This includes the route (a series of GPS coordinates), timestamps, speeds, and a summary of each trip (distance, duration, SOC usage, etc.).

*   **Notification Tokens and Endpoints:** If you enable push notifications, we store the data required to deliver them, depending on the channel you use:
    *   **FCM / APNs:** Your device token.
    *   **UnifiedPush:** The endpoint URL provided by your UnifiedPush distributor app.
    *   **NTFY:** Your configured NTFY server URL and topic.
    Push notification settings can be configured per vehicle.

*   **API Keys:** If you create API keys for programmatic access, we store a non-reversible hash of the key and its associated metadata (e.g., name, expiry date).

*   **Server Access Logs:** For security and maintenance, our server automatically logs standard request information, which may include your IP address, browser type, and the date and time of your request.

## 2. How We Use Your Information

We use the information we collect strictly to:

*   **Provide and Maintain the Service:** Authenticate your devices, route data, and display your vehicle's real-time and historical status.
*   **Send Notifications:** Deliver alerts from your vehicle to your configured devices or email address, as per your settings.
*   **Troubleshooting and Security:** Analyze server and vehicle logs to diagnose issues, monitor for security threats, and improve the service's stability and performance.

## 3. Data Sharing and Third Parties

We do not sell, rent, or share your personal information with third-party companies for their marketing purposes.

Data is shared with third-party services only when essential for specific features you choose to use:

*   **Push Notification Services:** Notification content is delivered via the channel you configure:
    *   **FCM:** Your device token and notification content are sent to Google's Firebase Cloud Messaging service.
    *   **APNs:** Your device token and notification content are sent to Apple's Push Notification service.
    *   **UnifiedPush:** Notification content is sent to the endpoint URL provided by your chosen UnifiedPush distributor (e.g., a self-hosted relay). The server operator has no control over that distributor.
    *   **NTFY:** Notification content is sent to the configured NTFY server (default set by the server operator; can be customized per vehicle). If a third-party NTFY server such as ntfy.sh is used, that provider receives the notification content.
*   **Email Services:** To send email notifications or account verification links, your email address and the email content are processed by your configured email provider.

The operator of this server is responsible for the configuration of these third-party services.

## 4. Data Security

We take robust measures to protect your information, including:

*   **Encryption and Hashing:** All user and vehicle passwords are a stored using strong, modern hashing algorithms. Security keys (like for 2FA) are encrypted.
*   **Two-Factor Authentication (2FA):** We offer Time-based One-Time Password (TOTP) as a crucial security layer that you can enable for your account.
*   **Secure Connections:** We use encrypted connections (HTTPS) for all web and API traffic. Encrypted protocols (TLS-secured TCP and WSS for MQTT) are available for vehicle communication.
*   **Server Security:** Access to the server and its database is strictly controlled.

## 5. Data Retention

We retain your data according to the following schedule:

*   **Account and Vehicle Information:** Retained as long as your account is active.
*   **General Vehicle Data (Status, Location, etc.):** This is volatile data that is frequently overwritten. Older historical logs of this data are automatically purged after **7 days**.
*   **Trip Tracking Data:** Trip data is considered your personal historical log and is **stored indefinitely until you choose to delete it**. You have full control to delete individual trips at any time.

## 6. Your Rights and Control

You have full control over your data on this platform.

*   **Access and Update:** You can review and update your account information, vehicle details, and API keys at any time through the web interface.
*   **Data Deletion:**
    *   You can permanently delete individual trip records from the vehicle's "Trips" tab.
    *   You can permanently delete your entire account and all associated data (including vehicles, all historical data, trips, and API keys) from your profile page.
*   **These deletion actions are irreversible.**

## 7. Contact Us

If you have any questions about this Privacy Policy or your data, please contact the server administrator:

{{ YOUR NAME OR ORGANISATION }}  
[{{ YOUR EMAIL }}](mailto:{{ YOUR EMAIL }})  
[{{ LINK TO YOUR LEGAL NOTICE / IMPRINT }}]({{ LINK TO YOUR LEGAL NOTICE / IMPRINT }})