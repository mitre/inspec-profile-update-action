control 'SV-234846' do
  title 'The SUSE operating system must have a firewall system installed to immediately disconnect or disable remote access to the whole operating system.'
  desc 'Operating system remote access functionality must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of mission functions and the need to eliminate immediate or future remote access to organizational information systems.

SUSE operating systems are capable to immediately stop remote connections and services by a local system administrator.

To immediately disconnect or disable remote access, the firewall needs to be set into panic mode.

> sudo firewall-cmd --panic-on

To enable remote connection again, panic mode needs to be disabled.

> sudo firewall-cmd --panic-off'
  desc 'check', 'Verify "firewalld" is configured to protect the SUSE operating system. 

Run the following command:

> systemctl status firewalld.service
 firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; vendor preset: disabled)
   Active: active (running) since Wed 2019-11-06 10:58:11 CET; 24h ago
     Docs: man:firewalld(1)
 Main PID: 1105 (firewalld)
    Tasks: 2 (limit: 4915)
   CGroup: /system.slice/firewalld.service
           ??1105 /usr/bin/python3 -Es /usr/sbin/firewalld --nofork --nopid

If the service is not enabled, this is a finding.

If the service is not active, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enable the firewall service. This is needed to be able to immediately disconnect or disable remote access to the whole system.

Enable the "firewalld.service" by running the following command:

> sudo systemctl enable firewalld.service

Start the "firewalld.service" by running the following command:

> sudo systemctl start firewalld.service

To immediately disconnect or disable remote access the firewall needs to be set into panic mode.

> sudo firewall-cmd --panic-on

To enable remote connection again, panic mode needs to be disabled.

> sudo firewall-cmd --panic-off'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38034r618807_chk'
  tag severity: 'medium'
  tag gid: 'V-234846'
  tag rid: 'SV-234846r622137_rule'
  tag stig_id: 'SLES-15-010370'
  tag gtitle: 'SRG-OS-000298-GPOS-00116'
  tag fix_id: 'F-37997r618808_fix'
  tag 'documentable'
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
