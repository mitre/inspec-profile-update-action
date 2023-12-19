control 'SV-104229' do
  title 'Symantec ProxySG must be configured to prohibit or restrict the use of network services as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

ALGs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols, and services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. The ALG is a key network element for preventing these noncompliant ports, protocols, and services from causing harm to DoD information systems.

The network ALG must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary. Default and updated policy filters from the vendors will disallow older versions of protocols and applications and will address most known nonsecure ports, protocols, and/or services. However, sources for further policy filters are the IAVMs and the PPSM requirements.'
  desc 'check', %q(Obtain the SSP and PPSMCAL and vulnerability assessments with the site's security policy. Verify that identity-based, role-based, and/or attribute-based authorization is configured for access to proxied websites. Verify that security policies and rules are configured and applied.

1. Log on to the Web Management Console.
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". 
4. For each rule within each Web Access Layer, verify that the "Source" and "destination" column for each rule contains something other than "any" (any is the default value) as required in the site's SSP and the PPSMCAL.

If Symantec ProxySG is not configured to prohibit or restrict the use of network services as defined in the PPSM CAL and vulnerability assessments, this is a finding.)
  desc 'fix', %q(Obtain the SSP and PPSMCAL and vulnerability assessments with the site's security policy. Configure the ProxySG to perform resources by employing identity-based, role-based, and/or attribute-based authorization for access to proxied websites.

1. Log on to the Web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". 
4. For each Web Access Layer that is configured, right-click the "Source" and "destination" of each column and click "Set".
5. Select the users, groups, roles, ports, protocols, and attributes as required by the PPSMCAL.
6. Click File >> Install Policy on SG Appliance.)
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93461r1_chk'
  tag severity: 'high'
  tag gid: 'V-94275'
  tag rid: 'SV-104229r1_rule'
  tag stig_id: 'SYMP-AG-000300'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-100391r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
