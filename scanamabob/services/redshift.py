def client(context, **kwargs):
    ''' Return an Redshift client handle for the given context '''
    return context.session.client('redshift', **kwargs)

