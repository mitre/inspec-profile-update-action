control 'SV-69019' do
  title 'The ALG must fail to a secure state upon failure of initialization, shutdown, or abort actions.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Network elements that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes.

An example is a firewall that blocks all traffic rather than allowing all traffic when a firewall component fails (e.g., fail closed and do not forward traffic). This prevents an attacker from forcing a failure of the system in order to obtain access.

This applies to the configuration of the gateway or network traffic security function of the device. Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Verify the ALG function fails to a secure state upon failure of initialization, shutdown, or abort actions.

If the ALG function does not fail to a secure state upon failure of initialization, shutdown, or abort actions, this is a finding.'
  desc 'fix', 'Configure the ALG to fail to a secure state upon failure of initialization, shutdown, or abort actions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55395r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54773'
  tag rid: 'SV-69019r1_rule'
  tag stig_id: 'SRG-NET-000235-ALG-000118'
  tag gtitle: 'SRG-NET-000235-ALG-000118'
  tag fix_id: 'F-59631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
