import os
import sys

# Add the current directory to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Now import and run the main function
from codeguardian.main import main

if __name__ == "__main__":
    sys.exit(main())
