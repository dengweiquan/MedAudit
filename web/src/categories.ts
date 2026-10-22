// 资产类别划分（M6 类别化工作台）。
export type CategoryKey = 'db' | 'os' | 'mw' | 'api'

export function kindCategory(kind: string): CategoryKey | 'unknown' {
  if (kind.startsWith('db-')) return 'db'
  if (kind === 'host' || kind === 'service' || kind.startsWith('os-')) return 'os'
  if (kind.startsWith('mw-')) return 'mw'
  if (kind === 'api') return 'api'
  return 'unknown'
}

export interface DbEngine {
  kind: string
  label: string
  engine: string
  defaultPort: number
  dbField: 'dbname' | 'service'
  dbLabel: string
}

export const DB_ENGINES: DbEngine[] = [
  { kind: 'db-mysql', label: 'MySQL', engine: 'mysql', defaultPort: 3306, dbField: 'dbname', dbLabel: '数据库名' },
  { kind: 'db-sqlserver', label: 'SQL Server', engine: 'sqlserver', defaultPort: 1433, dbField: 'dbname', dbLabel: '数据库名' },
  { kind: 'db-oracle', label: 'Oracle', engine: 'oracle', defaultPort: 1521, dbField: 'service', dbLabel: '服务名 / SID' },
  { kind: 'db-postgres', label: 'PostgreSQL', engine: 'postgres', defaultPort: 5432, dbField: 'dbname', dbLabel: '数据库名' },
]

export function engineOfKind(kind: string): DbEngine | undefined {
  return DB_ENGINES.find(e => e.kind === kind)
}

export const MW_PRODUCTS = [
  { kind: 'mw-tomcat', label: 'Tomcat' },
  { kind: 'mw-weblogic', label: 'WebLogic' },
  { kind: 'mw-nginx', label: 'Nginx' },
  { kind: 'mw-iis', label: 'IIS' },
  { kind: 'mw-other', label: '其他中间件' },
]
