			'limit'						=> null
		];
		$options = zbx_array_merge($defOptions, $options);

		// editable + PERMISSION CHECK
		if (self::$userData['type'] != USER_TYPE_SUPER_ADMIN && !$options['nopermissions']) {
			if (($options['editable'] && !is_null($options['globalmacro'])) || self::$userData['ugsetid'] == 0) {
				return $options['countOutput'] ? '0' : [];
			}
			else {
				$sqlParts['from'][] = 'host_hgset hh';
				$sqlParts['from'][] = 'permission p';
				$sqlParts['where'][] = 'hm.hostid=hh.hostid';
				$sqlParts['where'][] = 'hh.hgsetid=p.hgsetid';
				$sqlParts['where'][] = 'p.ugsetid='.self::$userData['ugsetid'];

				if ($options['editable']) {
					$sqlParts['where'][] = 'p.permission='.PERM_READ_WRITE;
				}
			}
		}

		// global macro
		if (!is_null($options['globalmacro'])) {
			$options['groupids'] = null;
			$options['hostmacroids'] = null;
			$options['triggerids'] = null;
			$options['hostids'] = null;
			$options['itemids'] = null;
			$options['selectHostGroups'] = null;
			$options['selectTemplateGroups'] = null;
			$options['selectTemplates'] = null;
