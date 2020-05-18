def client(context, **kwargs):
    ''' Return an RDS client handle for the given context '''
    return context.session.client('rds', **kwargs)

