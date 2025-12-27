control 'SV-30698' do
  title 'Mobile device users must complete training on required content before being provided mobile devices or allowed access to DoD networks with a mobile device.'
  desc 'Users are the first line of security controls for CMD systems. They must be trained in using CMD security controls or the system could be vulnerable to attack.'
  desc 'check', 'Detailed Policy Requirements: 
This requirement applies to mobile operating system (OS) CMDs.

All mobile device users must receive required training on the following topics before they are provided a mobile device or allowed access to DoD networks with a mobile device. Training is divided into two groups: Group A (general topics) and Group B (device specific topics). DISA’s Smartphones and Tablets security course satisfies the requirement for Group A training topics. The course is located at: http://iase.disa.mil/eta/smartphone_tablet_v1/launchpage.htm.

a. Requirement that personally-owned PEDs are not used to transmit, receive, store, or process DoD information unless approved by the AO and the owner signs forfeiture agreement in case of a security incident.

b. Procedures for wireless device usage in and around classified processing areas.

c. Requirement that PEDs with digital cameras (still and video) are not allowed in any SCIF or other areas where classified documents or information is stored, transmitted, or processed.

d. Procedures for a data spill. 

e. Requirement that Over-The-Air (OTA) wireless software updates should only come from DoD-approved sources. 

f. When CMD Wi-Fi Service is used, the following training will be completed: 
- Procedures for setting up a secure Wi-Fi connection and verifying the active connection is to a known access point. 

- Approved connection options (i.e., enterprise, home, etc.). 

- Requirements for home Wi-Fi connections. 

- The Wi-Fi radio will be disabled by the user whenever a Wi-Fi connection is not being used.

- The Wi-Fi radio must never be enabled while the CMD is connected via a cable to a PC.

g. Do not discuss FOUO or classified information on non-secure (devices whose cryptographic modules protecting data in transit are not FIPS 140-2 certified or NSA Type-1 certified for voice) cellular phones, cordless phones, and two-way radios used for voice communications. 

h. Do not connect PDAs, smartphones, and tablets to any workstation that stores, processes, or transmits classified data.. 

i. The installation of user owned applications, including geo-location aware applications, on the mobile device will be based on the Command’s Mobile Device Personal Use Policy.

j. The use of the mobile OS device to view and/or download personal email will be based the Command’s Mobile Device Personal Use Policy.

k. The download of user owned data (music files, picture files, etc.) on the mobile device will be based the Command’s Mobile Device Personal Use Policy.

l. All radios on the mobile device (Wi-Fi, Bluetooth, near-field communications (NFC)) must be turned off when not needed. This does not apply to radios supporting voice and data communication over a wireless carrier’s cellular network, in which case continuous connectivity is permissible.

m. Procedure on how to disable Location Services on the device. Location Services must be disabled for all applications or enabled only for applications approved by the AO for location based services.

n. Connecting PDAs, smartphones, and tablets to any DoD workstation via a USB connection is prohibited. 

Note: Listing training requirements in the User Agreement is an acceptable procedure for informing/training users on many of the required training topics. 

Check Procedures: 
- Review site CMD training material to see if it contains the required content. 
Note: Some training content may be listed in the User Agreement signed by the user. 

- Verify site training records show that CMD users received required training and training occurred before the user was issued a CMD. Check training records for approximately five users, picked at random.

If training material does not contain required content, this is a finding.'
  desc 'fix', 'Have all mobile device users complete training on required content.'
  impact 0.3
  ref 'DPMS Target Smartphone Handheld Policy'
  tag check_id: 'C-31120r20_chk'
  tag severity: 'low'
  tag gid: 'V-24961'
  tag rid: 'SV-30698r6_rule'
  tag stig_id: 'WIR-SPP-006-01'
  tag gtitle: 'Mobile device users receive training on required content'
  tag fix_id: 'F-27591r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
