control 'SV-30692' do
  title 'A data spill (Classified Message Incident (CMI)) procedure or policy must be published for site CMDs.'
  desc 'When a data spill occurs on a CMD, classified or sensitive data must be protected to prevent disclosure. After a data spill, the CMD must either be wiped using approved procedures, or destroyed if no procedures are available, so classified or sensitive data is not exposed. If a data spill procedure is not published, the site may not use approved procedures to remediate after a data spill occurs and classified data could be exposed.'
  desc 'check', "Detailed Policy Requirements: 
This requirement applies to mobile operating system (OS) CMDs.

This requirement also applies to sensitive DoD information stored on mobile OS devices that are not authorized to connect to DoD networks or store/process sensitive DoD information. Sensitive DoD data or information is defined as any data/information that has not been approved for public release by the site/Command Public Affairs Officer (PAO).

In accordance with DoD policy, all components must establish Incident Handling and Response procedures. A CMI or “data spill” occurs when a classified email is inadvertently sent on an unclassified network and received on a wireless email device. Classified information may also be transmitted through some other form of file transfer to include web browser downloads and files transferred through tethered connections. CMDs are not authorized for processing classified data. 

A data spill also occurs if a classified document is attached to an otherwise unclassified email. For BlackBerry and Good Mobile Messaging systems, a data spill will only occur if the classified attached document is viewed or opened by the CMD user since the CMD system only downloads an attachment on the CMD if the user views or opens the attachment. The site's Incident Handling and Response procedures should reference NSA/CSS Storage Device Declassification Manual 9-12, Section 5, for smartphone destruction procedures. 

Check Procedures: 
Interview the IAO. Verify classified incident handling, response, and reporting procedures are documented in site CMD procedures or security policies. Mark as a finding if classified incident handling, response, and reporting procedures are not documented in site CMD procedures or security policies.

This requirement applies at both sites where CMDs are issued and managed and at sites where the CMD management server is located.

---At the CMD management server site, verify Incident Handling and Response procedures include actions to sanitize the CMD management server and email servers (e.g., Exchange, Oracle mail). 

---At CMD sites, verify Incident Handling and Response procedures include actions for incident reporting and actions to safeguard classified smartphone devices. The following actions will be followed for all CMDs involved in a data spill:

-BlackBerry CMDs: follow procedures in the DoD Data Spill Procedures Guide for BlackBerry Smartphones located at http://iase.disa.mil/stigs/net_perimeter/wireless/smartphone.html. 

-Windows Mobile, Android, and iOS CMDs: the CMD will be destroyed.

Mark as a finding if Incident Handling and Response procedures do not include required information."
  desc 'fix', 'Publish a Classified Message Incident (CMI) procedure or policy for the site.'
  impact 0.5
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-31114r4_chk'
  tag severity: 'medium'
  tag gid: 'V-24955'
  tag rid: 'SV-30692r4_rule'
  tag stig_id: 'WIR-SPP-003-01'
  tag gtitle: 'Publish data spill procedures for CMDs'
  tag fix_id: 'F-27582r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'VIIR-1, VIIR-2'
end
