def complicated_decision_engine(value):
    score = 0
    for i in range(30):
        if value > i:
            if value % 2 == 0:
                if value % 3 == 0:
                    if value % 5 == 0:
                        score += i
                    else:
                        score -= 1
                else:
                    if value % 7 == 0:
                        score += 2
                    else:
                        score += 1
            else:
                if value % 11 == 0:
                    score += 3
                else:
                    score -= 2
        else:
            score += 0
    return score
