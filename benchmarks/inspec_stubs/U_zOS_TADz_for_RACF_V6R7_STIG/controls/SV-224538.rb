control 'SV-224538' do
  title 'Tivoli Asset Discovery for zOS (TADz) STC and/or batch data sets are not properly protected.'
  desc 'Tivoli Asset Discovery for zOS (TADz) STC and/or batch data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(TADZSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZTAD0001)

For all (TADz) STC and/or batch data sets:

If the UPDATE or greater access is restricted to systems programming personnel and the product STC(s) and/or batch job(s) this is not a finding.

If any job scheduling products are in use and access is restricted to READ this is not a finding.

If auditors have READ access this is not a finding.'
  desc 'fix', "Grant update and alter access to Tivoli Asset Discovery for z/OS (TADz) STC and/or batch data sets are limited to systems programmers and TADz STC and/or batch jobs only. 
Grant Read access to any scheduling products that are in use.
 
Grant Read access to auditors at the ISSO's discretion.

Identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. Identify if any additional groups have update access for specific data sets, and assure that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be:
SYS3.TADZ

The following commands are provided as a sample for implementing dataset controls:

ad 'sys3.tadz.*.iq*.**' uacc(none) owner(daztech) -
      audit(success(update) failures(read)) -
      data('TADZ Output Data')
ad 'sys3.tadz.*.uiq.**' uacc(none) owner(daztech) -
      audit(success(update) failures(read)) -
      data('TADZ Output Data')
ad 'sys3.tadz.*.um.**' uacc(none) owner(daztech) -
      audit(success(update) failures(read)) -
      data('TADZ Output Data')

pe 'sys3.tadz.*.iq*.**' id(syspaudt) acc(a)
pe 'sys3.tadz.*.iq*.**' id(tadzmon) acc(a)
pe 'sys3.tadz.*.iq*.**' id(tadzinq) acc(a)
pe 'sys3.tadz.*.uiq.**' id(syspaudt) acc(a)
pe 'sys3.tadz.*.uiq.**' id(tadzmon) acc(a)
pe 'sys3.tadz.*.uiq.**' id(tadzinq) acc(a)
pe 'sys3.tadz.*.um.**' id(syspaudt) acc(a)
pe 'sys3.tadz.*.um.**' id(tadzmon) acc(a)
pe 'sys3.tadz.*.um.**' id(tadzinq) acc(a)"
  impact 0.5
  ref 'DPMS Target zOS TADz for RACF'
  tag check_id: 'C-26221r868555_chk'
  tag severity: 'medium'
  tag gid: 'V-224538'
  tag rid: 'SV-224538r868557_rule'
  tag stig_id: 'ZTADR001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26209r868556_fix'
  tag 'documentable'
  tag legacy: ['SV-28548', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
