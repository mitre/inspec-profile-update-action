control 'SV-16868' do
  title 'Guest operating system is not supported by ESX Server.'
  desc 'The guest OS on the ESX Server must be supported by VMware. Guest OS will need to be approved by VMware so that if problems are encountered with the guest OS, VMware can assist with the resolution.  Also, unsupported guest virtual machines create problems since no documentation or support is available from VMware.'
  desc 'check', 'The following table lists the supported OSs for each VMware product.  For the ESX Server, focus on column 4 in the Table.  If the table has a blank box, this means the operating system is not supported.  
1. Login to VirtualCenter with the VI Client. Select an ESX Server and review all the virtual machines.  
2. Review the OS of the virtual machines and verify that no “other” virtual machines are running.  “Other” virtual machines may be identified by logging into VirtualCenter with the VI Client and selecting the virtual machine from the inventory panel. Click Edit settings. Click Options > General Options.  Review the Guest Operating System and Version to obtain the guest operating system selection. If "other" is selected, this is a finding.  

.  
Guest Operating System	Workstation	VMware 
ACE	GSX 
Server   	ESX 
Server	VMware Server   	VMware Fusion
Windows Server 2008 
6.0.1–6.0.2	2.0.1–2.0.2	  	3.5	  	  
Windows Vista 
6.0–6.0.2	2.0–2.0.2	  	3.0–3.5	  	1.0–1.1.1
Windows Server 2003 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–3.5	1.0–1.0.4	1.0–1.1.1
Windows XP 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–3.5	1.0–1.0.4	1.0–1.1.1
Windows 2000 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–3.5	1.0–1.0.4	1.0–1.1.1
Windows NT 4.0 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–3.5	1.0–1.0.4	1.0–1.1.1
Windows Me 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	1.0–1.1.1
Windows 98 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	1.0–1.1.1
Windows 95 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	1.0–1.1.1
DOS and Windows 3.1x 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	1.0–1.1.1
Mandriva Corporate Server 4 
5.5.3–6.0.2	2.0–2.0.2	 	 	 	  
Mandriva Linux 2007 
5.5.3–6.0.2	2.0–2.0.2	 	 	 	1.0–1.1.1
Mandriva Linux 2006 
5.5.2–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	1.0–1.1.1
Mandrake Linux 10.1 
5.5–6.0.2	2.0–2.0.2	3.2–3.2.1	 	1.0–1.0.4	  
Mandrake Linux 10 
5.0–6.0.2	2.0–2.0.2	3.2–3.2.1	 	1.0–1.0.4	  
Mandrake Linux 9.2 
5.0–6.0.2	2.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Mandrake Linux 9.1 
 	 	3.1–3.2.1	 	 	  
Mandrake Linux 9.0 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Mandrake Linux 8.2 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Mandrake Linux 8.0 and 8.1 
 	 	3.0–3.2.1	 	 	  
Novell Linux Desktop 9 
5.0–6.0.2	1.0–2.0.2	 	 	1.0–1.0.4	1.0–1.1.1
Red Hat Enterprise Linux 5 
5.5.3–6.0.2	2.0–2.0.2	 	3.0.2–3.5	 	1.0–1.1.1
Red Hat Enterprise Linux 4 
5.0–6.0.2	1.0.1–2.0.2	3.2–3.2.1	2.5.2–3.5	1.0–1.0.4	1.0–1.1.1
Red Hat Enterprise Linux 3 
4.5–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0.1–3.5	1.0–1.0.4	1.0–1.1.1
Red Hat Enterprise Linux 2.1 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–3.5	1.0–1.0.4	1.0–1.1.1
Red Hat Linux 9.0 
4.0.1–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–2.5.5	1.0–1.0.4	1.0–1.1.1
Red Hat Linux 8.0 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–2.5.5	1.0–1.0.4	  
Red Hat Linux 7.3 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–2.5.5	1.0–1.0.4	  
Red Hat Linux 7.2 
4.0–6.0.2	1.02.0.2	3.0–3.2.1	2.0–2.5.5	1.0–1.0.4	  
Red Hat Linux 7.1 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Red Hat Linux 7.0 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	1.0–1.1.1
Red Hat Linux 6.2 
 	 	3.0–3.2.1	 	 	  
Sun Java Desktop System 2 
5.0–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	  
SUSE Linux Enterprise Server 10 
5.5.2–6.0.2	2.0–2.0.2	 	3.0.1–3.5	1.0–1.0.4	1.0–1.1.1
SUSE Linux Enterprise Server 9 
5.0–6.0.2	1.0.1–2.0.2	3.2–3.2.1	2.5–3.5	1.0–1.0.4	  
SUSE Linux Enterprise Server 8 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–3.5	1.0–1.0.4	  
SUSE Linux Enterprise Server 7 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Open SUSE Linux 10.3 
6.0.1–6.0.2	2.0.1–2.0.2	 	 	  	  
Open SUSE Linux 10.2 
6.0–6.0.2	2.0–2.0.2	 	 	  	  
SUSE Linux 10.1 
5.5.2–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	1.0–1.1.1
SUSE Linux 10 
5.5–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	  
SUSE Linux 9.3 
5.5–6.0.2	2.0–2.0.2	 	2.5.2–2.5.5	1.0–1.0.4	1.0–1.1.1
SUSE Linux 9.2 
5.0–6.0.2	1.0.1–2.0.2	3.2–3.2.1	2.5.1–2.5.5	1.0–1.0.4	  
SUSE Linux 9.1 
4.5.2–6.0.2	1.0–2.0.2	3.1–3.2.1	2.5–2.5.5	1.0–1.0.4	  
SUSE Linux 9.0 
4.5–6.0.2	1.0–2.0.2	3.0–3.2.1	2.1–2.5.5	1.0–1.0.4	  
SUSE Linux 8.2 
4.0.1–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0–2.5.5	1.0–1.0.4	  
SUSE Linux 8.1 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
SUSE Linux 8.0 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
SUSE Linux 7.3 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Turbolinux 10 Server 
6.0.1–6.0.2	2.0.1–2.0.2	  	  	  	  
Turbolinux 10 Desktop 
5.5–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	1.0–1.1.1
Turbolinux Enterprise Server 8 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	1.0–1.1.1
Turbolinux Workstation 8 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Turbolinux 7.0 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Ubuntu Linux 7.04 
6.0–6.0.2	2.0–2.0.2	 	3.0.2–3.5	 	  
Ubuntu Linux 6.10 
6.0–6.0.2	2.0–2.0.2	  	  	  	1.0–1.1.1
Ubuntu Linux 6.06 
5.5.2–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	  
Ubuntu Linux 5.10 
5.5–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	1.0–1.1.1
Ubuntu Linux 5.04 
5.5–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	  
FreeBSD 6.2 
6.0.1–6.0.2	2.0.1–2.0.2	  	  	  	  
FreeBSD 6.1 
5.5.2–6.0.2	2.0–2.0.2	 	 	 	1.0–1.1.1
FreeBSD 6.0 
5.5.2–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	  
FreeBSD 5.5 
5.5–6.0.2	2.0–2.0.22	  	  	1.0–1.0.4	1.0–1.1.1
FreeBSD 5.4 
5.5–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	  
FreeBSD 5.3 
5.5–6.0.2	2.0–2.0.2	 	 	1.0–1.0.4	  
FreeBSD 5.2 
5.0–6.0.2	2.0–2.0.2	3.1–3.2.1	 	1.0–1.0.4	  
FreeBSD 5.1 
5.0–6.0.2	2.0–2.0.2	3.2–3.2.1	 	1.0–1.0.4	  
FreeBSD 5.0 
4.5–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
FreeBSD 4.11 
 	 	 	2.5.4–2.5.5	 	  
FreeBSD 4.10 
 	 	 	2.5–2.5.5	 	  
FreeBSD 4.9 
 	 	3.2–3.2.1	2.5	 	  
FreeBSD 4.4, 4.5, 4.6.2, 4.8 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
FreeBSD 4.0, 4.1, 4.2, 4.3 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
NetWare 6.5 Server 
4.5–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0.1–3.5	1.0–1.0.4	1.0–1.1.1
NetWare 6.0 Server 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0.1–3.5	1.0–1.0.4	  
NetWare 5.1 Server 
4.0–6.0.2	1.0–2.0.2	3.0–3.2.1	2.0.1–3.5	1.0–1.0.4	  
NetWare 4.2 Server 
5.5.2–6.0.2	2.0–2.0.2	3.0–3.2.1	 	1.0–1.0.4	  
Solaris 10 Operating System for x86 Platforms 
4.5.2–6.0.2	1.0–2.0.2	3.1–3.2.1	3.0–3.5	1.0–1.0.4	1.0–1.1.1
Solaris 9 Operating System x86 Platform Edition 
4.5.2–6.0.2	1.0–2.0.2	3.1–3.2.1	 	1.0–1.0.4'
  desc 'fix', 'Use only supported operating systems on the ESX Server.'
  impact 0.7
  ref 'DPMS Target VMware Virtual Machine 3.x/4.x'
  tag check_id: 'C-16278r1_chk'
  tag severity: 'high'
  tag gid: 'V-15926'
  tag rid: 'SV-16868r1_rule'
  tag stig_id: 'ESX1190'
  tag gtitle: 'Guest OS is not supported by ESX Server'
  tag fix_id: 'F-15876r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Guest Administrator]']
  tag ia_controls: 'ECSC-1'
end
