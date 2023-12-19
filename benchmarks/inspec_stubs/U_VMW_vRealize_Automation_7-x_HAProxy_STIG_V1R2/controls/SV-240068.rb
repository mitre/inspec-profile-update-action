control 'SV-240068' do
  title 'HAProxy must be configured to validate the configuration files during start and restart events.'
  desc "Failure in a known state can address safety or security in accordance with the mission/business needs of the organization. Failure in a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Failure in a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Applications or systems that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption of mission/business processes. An example is a firewall that blocks all traffic rather than allowing all traffic when a firewall component fails. This prevents an attacker from forcing a failure of the system in order to obtain access. 

Web servers must fail to a known consistent state. Validating the server's configuration file during start and restart events can help to minimize the risk of an unexpected server failure during system start."
  desc 'check', %q(At the command prompt, execute the following command:

grep -E '\s(start|restart)\\)' -A 7 /etc/init.d/haproxy

If the command "haproxy_check" is not shown in the "start)" and the "restart)" code blocks, this is a finding.)
  desc 'fix', 'Navigate to and open /etc/init.d/haproxy

Navigate to the "start)" code block. Add the value "haproxy_check" before the line with the value "/sbin/startproc". 

Navigate to the "restart)" code block. Add the value "haproxy_check" before the line with the value "$0 stop".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43301r665371_chk'
  tag severity: 'medium'
  tag gid: 'V-240068'
  tag rid: 'SV-240068r879640_rule'
  tag stig_id: 'VRAU-HA-000280'
  tag gtitle: 'SRG-APP-000225-WSR-000140'
  tag fix_id: 'F-43260r665372_fix'
  tag 'documentable'
  tag legacy: ['SV-99823', 'V-89173']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
