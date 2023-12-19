control 'SV-234821' do
  title 'The SUSE operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

SUSE operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the SUSE operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or address authorized quality-of-life issues.

'
  desc 'check', 'Verify the SUSE operating system is configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.

Check that the "firewalld.service" is enabled and running by running the following command:

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

If the service is not active, this is a finding.

Check the firewall configuration for any unnecessary or prohibited functions, ports, protocols, and/or services by running the following command:

> sudo firewall-cmd --list-all

Ask the System Administrator for the site or program PPSM Component Local Services Assessment (Component Local Services Assessment (CLSA). Verify the services allowed by the firewall match the PPSM CLSA. 

If there are any additional ports, protocols, or services that are not included in the PPSM CLSA, this is a finding.

If there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system is configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.

Add/modify /etc/firewalld configuration files to comply with the PPSM CAL.

Enable the "firewalld.service" by running the following command:

> sudo systemctl enable firewalld.service

Start the "firewalld.service" by running the following command:

> sudo systemctl start firewalld.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38009r618732_chk'
  tag severity: 'medium'
  tag gid: 'V-234821'
  tag rid: 'SV-234821r854186_rule'
  tag stig_id: 'SLES-15-010220'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-37972r618733_fix'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000297-GPOS-00115', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag cci: ['CCI-000382', 'CCI-002314']
  tag nist: ['CM-7 b', 'AC-17 (1)']
end
