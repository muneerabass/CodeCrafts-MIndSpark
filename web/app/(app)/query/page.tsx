import { api } from '@/lib/api';
import type { List, QuerySchema, SavedQuery } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { QueryEditor } from './editor';

export const metadata = { title: 'Query' };

export default async function QueryPage() {
  const [schema, saved] = await Promise.all([api<QuerySchema>('/query/schema'), api<List<SavedQuery>>('/queries')]);
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Query' }]}
        info="Ask your own questions with read-only SQL over this tenant's inventory views. Results are capped at 1,000 rows and queries time out after 10 seconds."
        actions={null}
      />
      <QueryEditor schema={schema} saved={saved.items} />
    </>
  );
}
