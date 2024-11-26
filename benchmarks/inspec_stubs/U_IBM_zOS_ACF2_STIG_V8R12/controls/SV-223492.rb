control 'SV-223492' do
  title 'ACF2 BLPPGM GSO record must not be defined.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET CONTROL(GSO)
LIST BLPPGM

If the BLPPGM record is defined, this is a finding.'
  desc 'fix', 'The BLPPGM GSO value indicates that ACF2 does not control the programs authorized to use tape bypass label processing (BLP).

Delete the BLPPGM from GSO options.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25165r500608_chk'
  tag severity: 'medium'
  tag gid: 'V-223492'
  tag rid: 'SV-223492r533198_rule'
  tag stig_id: 'ACF2-ES-000740'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25153r500609_fix'
  tag 'documentable'
  tag legacy: ['SV-106787', 'V-97683']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
