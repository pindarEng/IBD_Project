try:
    import numpy as np
    print("numpy version", np.__version__)
except ImportError:
    raise ImportError("numpy not installed")

try:
    import pandas as pd
    print("pandas version", pd.__version__)
except ImportError:
    raise ImportError("pandas not installed")

