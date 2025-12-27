control 'SRG-NET-000235-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Network elements that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes. 

An example is a firewall that blocks all traffic rather than allowing all traffic when a firewall component fails (e.g., fail closed and do not forward traffic). This prevents an attacker from forcing a failure of the system in order to obtain access. This applies to the configuration of the functionality of the element (e.g., firewall, IDPS, or router). Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Verify the Unified Communications Session Manager fails to a secure state when system initialization fails, shutdown fails, or aborts fail.

If the Unified Communications Session Manager does not fail to a secure state if system initialization fails, shutdown fails, or aborts fail, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000235-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000235-VVSM-00101'
  tag rid: 'SRG-NET-000235-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000235-VVSM-00101'
  tag gtitle: 'SRG-NET-000235-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000235-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
