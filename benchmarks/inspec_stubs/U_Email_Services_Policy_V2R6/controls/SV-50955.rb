control 'SV-50955' do
  title 'Email client services for Commercial Mobile Devices must be documented in the Email Domain Security Plan (EDSP).'
  desc 'Commercial Mobile Devices (CMDs) introduce additional IA concerns to email systems because of the additional guidance pertaining specifically to CMDs. The Department of Defense (DoD) Chief Information Officer (CIO) put forth specific guidance concerning CMD implementation on 6 Apr 2011. The memo states, "Email redirection from the email server (e.g., Exchange Server) to the device shall be controlled via centrally managed server." Therefore the native clients used on CMD cannot access the email system directly but instead must be managed by mobile email management (MEM) services. 

The Exchange configuration relies on Exchange ActiveSync (EAS) as the client communication protocol. Natively, EAS is an inbound initiated, bidirectional protocol, which is problematic for DoD networks. Acceptable implementations avoid inbound initiated connections and use external secure network operation centers (NOC) in secure tunnels from the management servers residing in the DoD to the NOC and from the NOC to the CMD.

For email systems that do not deliver email directly to the device but rather use browser access to DoD email systems, this requirement would not apply but client-access path guidance does (EMG3-108 Email).

The EDSP must include the functional architecture of the integration of the email system, required MEM, NOC if used, and CMDs. Protocols communicating with the CMD or NOC must be secured to protect sensitive DoD data from being compromised using accepted FIPS 140-2 approved modules.'
  desc 'check', 'For systems not providing Internet-sourced email client services to CMDs, this check is N/A.

Access the Email Domain Security Plan (EDSP) for email systems. Review for functional architecture of the email system for all required components, including the MEM, NOC, CMDs, etc., when providing service to CMDs. Confirm the design requires secure communication from the email system to the MEM. Verify the MEM, NOC, and CMDs are approved for use in DoD. If the email domain employs the required architecture and is documented in the EDSP, this is not a finding.

If the architecture uses the EAS protocol to Commercial Mobile Devices (CMD) without connecting through external secure NOCs and encapsulating in a secure tunnel from the management servers residing in the DoD to the NOC and from the NOC to the CMD, this is a finding.  If the use of EAS is not documented in the EDSP, this is a finding.'
  desc 'fix', 'Email client services to Commercial Mobile Devices, including the required components of the architecture, must be documented in the Email Domain Security Plan (EDSP).'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-46505r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39139'
  tag rid: 'SV-50955r4_rule'
  tag stig_id: 'EMG3-055 EMail'
  tag gtitle: 'EMG3-055 EMail Security for CMD'
  tag fix_id: 'F-44116r1_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'DCFA-1'
end
