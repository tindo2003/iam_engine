// Reusable retrieval-practice quiz widget for teach/lessons/*.html
//
// Markup contract:
// <div class="quiz" data-answer="b"
//      data-feedback-correct="..." data-feedback-incorrect="...">
//   <p class="quiz-question">...</p>
//   <div class="quiz-options">
//     <button class="quiz-option" data-key="a">...</button>
//     <button class="quiz-option" data-key="b">...</button>
//   </div>
//   <p class="quiz-feedback" hidden></p>
// </div>
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".quiz").forEach((quiz) => {
    const answer = quiz.dataset.answer;
    const feedback = quiz.querySelector(".quiz-feedback");

    quiz.querySelectorAll(".quiz-option").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (quiz.classList.contains("answered")) return;
        quiz.classList.add("answered");

        const chosen = btn.dataset.key;
        const isCorrect = chosen === answer;

        quiz.querySelectorAll(".quiz-option").forEach((b) => {
          b.disabled = true;
          if (b.dataset.key === answer) b.classList.add("quiz-correct");
        });
        if (!isCorrect) btn.classList.add("quiz-incorrect");

        feedback.hidden = false;
        feedback.textContent = isCorrect
          ? quiz.dataset.feedbackCorrect || "Correct."
          : quiz.dataset.feedbackIncorrect || "Not quite — correct answer highlighted above.";
        feedback.className = "quiz-feedback " + (isCorrect ? "quiz-feedback-correct" : "quiz-feedback-incorrect");
      });
    });
  });
});
