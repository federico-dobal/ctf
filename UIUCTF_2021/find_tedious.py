import angr
import sys

def main(argv):
  path_to_binary = './challenge_tedious'  # :string
  project = angr.Project(path_to_binary)

  initial_state = project.factory.entry_state()
  print(initial_state)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    print(stdout_output)
    return 'GOOD JOB' in stdout_output.decode("utf-8")

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    print(stdout_output)
    return 'WRONG' in stdout_output.decode("utf-8")

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    print('Found')
    solution_state = simulation.found[0]
    print(solution_state)
    print (solution_state.posix.dumps(sys.stdin.fileno()))
  else:
    print('Not Found')
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
