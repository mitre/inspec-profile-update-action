control 'SV-3503' do
  title 'WLAN-capable devices must not use wireless peer-to-peer networks to connect to other devices.'
  desc 'WLANs may be configured into a peer-to-peer (also known as ad hoc) network that permits devices to communicate directly rather than through an access point.  It is difficult to ensure required IA mechanisms are in place for such networks, because they inherently are not subject to centralized management.  Consequently, there is a significant risk an adversary will defeat or circumvent authentication or encryption controls (if they even exist) on a peer-to-peer or ad hoc WLANs.'
  desc 'check', '1. Use the site’s WIDS capability or any WLAN capable device to identify available WLAN connections.  If the scan reveals there are devices supporting anything other than infrastructure connections (i.e., connections using peer-to-peer services rather via an access point), then record the advertised network names of these devices. Work with the SA or IAO to determine if any of these devices is associated with the site.  
2. Check a sample (3-4) of  WLAN client devices at the site.  In the WLAN client management software, verify that the WLAN interfaces are configured to support WLAN infrastructure connections only.  This may be indicated by check boxes stating “Infrastructure mode only” or  “Connect to access point only” or 
“Disable peer-to-peer networking”.  
3. Mark as a finding if:
- If there are any WLAN clients advertising their availability for ad hoc WLAN connections. 
- If there are WLAN clients that have not configured WLAN interfaces to support infrastructure connections only (and thus prohibiting peer-to-peer or ad hoc connections).
4. Notify the IAM or IAO if there devices unaffiliated with the site advertising their availability for WLAN connections.  This is not a finding because such devices are not under the site’s control, but they nonetheless pose an IA risk to the site of which IA and other personnel should be aware.'
  desc 'fix', 'Configure WLAN client interfaces to support infrastructure connections only.  Procure WLAN software and devices that have the capability to turn off or otherwise disable peer-to-peer WLAN communications.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-4002r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3503'
  tag rid: 'SV-3503r1_rule'
  tag stig_id: 'WIR0165'
  tag gtitle: 'No peer-to-peer WLANs'
  tag fix_id: 'F-4561r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1, ECWN-1'
end
