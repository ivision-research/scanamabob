def client(context, **kwargs):
    ''' Return an ELB client handle for the given context '''
    return context.session.client('elb', **kwargs)

def v2_client(context, **kwargs):
    ''' Return an ELBv2 client handle for the given context '''
    return context.session.client('elbv2', **kwargs)
