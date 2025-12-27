control 'SV-104269' do
  title 'Symantec ProxySG must fail to a secure state upon failure of initialization, shutdown, or abort actions.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Network elements that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes.

An example is a firewall that blocks all traffic rather than allowing all traffic when a firewall component fails (e.g., fail closed and do not forward traffic). This prevents an attacker from forcing a failure of the system to obtain access.

Depending on the deployment architecture, there are many configurations to check external to the ProxySG to ensure that failures of initialization, shutdown, or abort actions result in a secure state. With these external configurations in place, the ProxySG meets this requirement inherently. However, if a ProxySG hardware appliance is configured in a transparent, physically in-path manner, the check and fix apply.'
  desc 'check', 'Verify that the transparent, physically in-line hardware ProxySG appliance is configured to fail securely in the event of failures of initialization, shutdown, or abort actions.

1. Browse to Configuration >> Network >> Adapters >> Bridges. 
2. Select the appropriate bridge-pair (whichever is in use) and click "Edit". 
3. Verify that the "fail-closed" radio button is selected. 

If the "failed-closed" radio button is not selected, this is a finding.'
  desc 'fix', 'Configure the transparent, physically in-line hardware ProxySG appliance to fail securely in the event of failures of initialization, shutdown, or abort actions.

1. Browse to Configuration >> Network >> Adapters >> Bridges.
2. Select the appropriate bridge-pair (whichever is in use) and click "Edit". 
3. Select the "fail-closed" radio button and click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93501r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94315'
  tag rid: 'SV-104269r1_rule'
  tag stig_id: 'SYMP-AG-000510'
  tag gtitle: 'SRG-NET-000235-ALG-000118'
  tag fix_id: 'F-100431r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
