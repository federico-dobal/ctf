import angr
import sys
import claripy

def main(argv):
  path_to_binary = './signals'
  project = angr.Project(path_to_binary)
  arg = claripy.BVS('arg',75*8) #set a bit vector for argv[1]

  initial_state = project.factory.entry_state(args=[path_to_binary, arg])
  print(initial_state)

  for byte in arg.chop(8):
      #initial_state.add_constraints(byte != '\x00')
      #initial_state.add_constraints(byte != '\x0f')
      initial_state.add_constraints(byte >= 0x20)
      initial_state.add_constraints(byte <= 0x7F)

  initial_state.add_constraints(arg.chop(8)[0] == 'u')
  initial_state.add_constraints(arg.chop(8)[1] == 'i')
  initial_state.add_constraints(arg.chop(8)[2] == 'u')
  initial_state.add_constraints(arg.chop(8)[3] == 'c')
  initial_state.add_constraints(arg.chop(8)[4] == 't')
  initial_state.add_constraints(arg.chop(8)[5] == 'f')
  initial_state.add_constraints(arg.chop(8)[6] == '{')

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno()).decode("utf-8")
    print(stdout_output)
    return 'Challenge broke' in stdout_output

  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno()).decode("utf-8")
    print(stdout_output)
    return 'incorrect' in stdout_output

  simulation.explore(find=0x401313, avoid=should_abort)

  if simulation.found:
    print('Found')
    solution_state = simulation.found[0]
    print(solution_state)
    print (solution_state.posix.dumps(sys.stdin.fileno()).decode("utf-8"))
    print(solution_state.solver.eval(arg,cast_to=bytes))
  else:
    print('Not Found')
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
