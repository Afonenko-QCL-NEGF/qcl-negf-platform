"""Read-only, bounded absence proof for the two owned workflows and CalcJobs."""
import json
import sys

WORKFLOWS=('aiida.workflows:qcl_negf.plan','aiida.workflows:qcl_negf.execution_restart')
CALCULATION='aiida.calculations:qcl_negf.execution'
TERMINAL=('finished','killed','excepted')

def nonterminal_filter(process_types):
    # NOT IN alone loses SQL/JSON NULL and absent attributes.
    return {'process_type':{'in':list(process_types)},'or':[
        {'attributes':{'!has_key':'process_state'}},
        {'attributes.process_state':{'==':None}},
        {'attributes.process_state':{'!in':list(TERMINAL)}}]}

def inspect_profile(orm,profile):
    if profile!='qcl-negf':raise ValueError('Unexpected loaded profile')
    result={'schema':'qcl-negf-aiida-update-check-v1','profile':profile,
        'roots_checked':False,'calcjobs_checked':False,'active_root_found':False,
        'active_calcjob_found':False,'root_sample':None,'calcjob_sample':None}
    for label,kind,types,project in (
        ('root',orm.WorkChainNode,WORKFLOWS,['uuid','process_type','attributes.process_state','attributes.paused']),
        ('calcjob',orm.CalcJobNode,(CALCULATION,),['uuid','attributes.process_state'])):
        query=orm.QueryBuilder().append(kind,filters=nonterminal_filter(types),project=project).limit(1)
        rows=query.all()
        if not isinstance(rows,list) or len(rows)>1:raise ValueError('Unsupported query result')
        result['roots_checked' if label=='root' else 'calcjobs_checked']=True
        if rows:
            row=rows[0]
            if len(row)!=len(project):raise ValueError('Incomplete process projection')
            if not isinstance(row[0],str) or len(row[0])>64:raise ValueError('Invalid bounded process UUID')
            state=row[2] if label=='root' else row[1]
            if state is not None and (not isinstance(state,str) or len(state)>64):raise ValueError('Unknown state type')
            if state in TERMINAL:raise ValueError('Query predicate failed terminal exclusion')
            sample={'uuid':row[0],'process_state':state}
            if label=='root':
                if row[1] not in WORKFLOWS or row[3] not in (True,False,None):raise ValueError('Invalid workflow projection')
                sample.update(process_type=row[1],paused=row[3] is True)
            result['active_'+label+'_found']=True;result[label+'_sample']=sample
    if len(json.dumps(result).encode())>4096:raise ValueError('Update query output exceeds bound')
    return result

def main():
    from aiida import orm
    from aiida.manage import get_manager
    profile=get_manager().get_profile()
    if profile is None:raise ValueError('No loaded profile')
    print(json.dumps(inspect_profile(orm,profile.name),sort_keys=True))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('AiiDA update query unknown: '+type(error).__name__,file=sys.stderr);raise SystemExit(1)
