control 'SV-254568' do
  title 'Rancher RKE2 must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after five minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating-system-level network connection. This does not mean that the application terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Ensure streaming-connection-idle-timeout argument is set correctly.

Run this command on each node:
/bin/ps -ef | grep kubelet | grep -v grep

If --streaming-connection-idle-timeout is set to < "5m" or the parameter is not configured, this is a finding.'
  desc 'fix', 'Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc/rancher/rke2/config.yaml, to contain the following:

kubelet-arg:
- streaming-connection-idle-timeout=5m

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58052r894462_chk'
  tag severity: 'medium'
  tag gid: 'V-254568'
  tag rid: 'SV-254568r894464_rule'
  tag stig_id: 'CNTR-R2-000890'
  tag gtitle: 'SRG-APP-000190-CTR-000500'
  tag fix_id: 'F-58001r894463_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
