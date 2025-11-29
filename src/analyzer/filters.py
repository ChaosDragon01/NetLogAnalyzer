
class Filters:
    def __init__(self):
        self.filters = []

    def add_filter(self, filter_func):
        self.filters.append(filter_func)

    def apply_filters(self, data):
        for filter_func in self.filters:
            data = filter_func(data)
        return data
    

    