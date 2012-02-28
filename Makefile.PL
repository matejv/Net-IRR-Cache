# Copyright (C) 2012 Academic and Research Network of Slovenia (Arnes).
# All Rights Reserved.
# 
# This file is part of Route Server Manager (RS Manager).
# 
# RS Manager is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, version 2.0 of the License.
# 
# RS Manager is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
# 
# You should have received a copy of the GNU General Public License v2.0
# along with RS Manager.  If not, see:
# 
# http://www.gnu.org/licenses/gpl-2.0.html
#

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME            => 'Net::IRR::Cache',
	VERSION_FROM    => 'lib/Net/IRR/Cache.pm',

	PREREQ_PM => {
		YAML::Tiny => 0,
	},

	dist => {
		COMPRESS => 'gzip',
		SUFFIX => '.gz',
	},
);