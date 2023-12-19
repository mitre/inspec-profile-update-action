control 'SV-8758' do
  title 'An Intrusion Detection and Prevention System (IDPS) must be deployed to monitor all unencrypted traffic entering and leaving the enclave.'
  desc 'Per CJCSI 6510.01F, Enclosure A-5, Paragraph 8,  “DOD ISs (e.g., enclaves, applications, outsourced IT-based process, and platform IT interconnections) shall be monitored to detect and react to incidents, intrusions, disruption of services, or other unauthorized activities (including insider threat) that threaten the security of DOD operations or IT resources, including internal misuse.”

An Intrusion Prevention System (IPS) allows the sensor to monitor, alert, and actively attempt to drop/block malicious traffic.  An Intrusion Detection System (IDS) uses a passive method; receiving a copy of the packets to analyze and alert authorized persons about any malicious activity.  While an IDS or an IPS in a passive role cannot stop the attack itself, it can typically notify and dynamically assign ACLs or other rules to a firewall or router for filtering.  The preferred method of installation is to have the IDPS configured for inline mode.  Only when there is a valid technical reason, should the IDPS be placed into a passive or IDS mode.  For a full uninhibited view of the traffic, the IDPS must sit behind the enclave’s firewall.  This will allow the IDPS to monitor all traffic unencrypted, entering or leaving the enclave.'
  desc 'check', 'Review the network topology to ensure the enclave has the IDPS positioned to monitor all traffic to and from the enclave. Review any type of report that was recently produced from information provided by the sensor showing any recent alerts, an escalation activity and any type of log or configuration changes.  This will show the sensor is being actively monitored and alerts are being acted upon. If the enclave’s CNDSP requires continuous monitoring of the IDPS, the CNDSPs management team (e.g. sensor grid management team at DISA) will verify the operational status by providing information about the enclave’s IDPS such as a network diagram, MOA, current alert information, or other information to validate its operational status.

If there is no IDPS positioned and enabled to monitor all ingress and egress traffic, this is a finding.

Exception: If the perimeter security for the enclave or B/C/P/S is provisioned via the JRSS, then this requirement is not applicable.'
  desc 'fix', 'Install an IDPS inline or passively, behind the enclave firewall to monitor all unencrypted traffic, inbound and outbound.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-3692r5_chk'
  tag severity: 'medium'
  tag gid: 'V-8272'
  tag rid: 'SV-8758r3_rule'
  tag stig_id: 'NET-IDPS-021'
  tag gtitle: 'IDPS is not monitoring traffic unencrypted traffic behind the firewall.'
  tag fix_id: 'F-7899r5_fix'
  tag 'documentable'
  tag cci: ['CCI-001097', 'CCI-001255', 'CCI-002668']
  tag nist: ['SC-7 a', 'SI-4 c 1', 'SI-4 (11)']
end
